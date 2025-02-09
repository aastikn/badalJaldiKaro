import boto3
import json
import logging
import time
import tempfile
import zipfile
from datetime import datetime
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Set, Optional
from enum import Enum
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
import requests
import networkx as nx
import matplotlib.pyplot as plt

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('CloudScanner')

class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"

class ResourceType(Enum):
    COMPUTE = "compute"
    SERVERLESS = "serverless"
    DATABASE = "database"
    STORAGE = "storage"
    QUEUE = "queue"
    NETWORK = "network"
    CONTAINER = "container"
    CACHE = "cache"
    API = "api"
    IDENTITY = "identity"

@dataclass
class CloudResource:
    id: str
    name: str
    provider: CloudProvider
    type: ResourceType
    region: str
    properties: Dict
    dependencies: Set[str] = None
    tags: Dict = None
    created_at: Optional[datetime] = None
    last_modified: Optional[datetime] = None

    def __post_init__(self):
        self.dependencies = self.dependencies or set()
        self.tags = self.tags or {}

class CloudScanner(ABC):
    @abstractmethod
    def authenticate(self) -> bool: 
        pass
    @abstractmethod
    def scan_resources(self) -> List[CloudResource]:
        pass
    @abstractmethod
    def get_dependencies(self, resource: CloudResource) -> Set[str]:
        pass

class AWSScanner(CloudScanner):
    def __init__(self, region: str, profile: str = None, session: boto3.Session = None):
        self.region = region
        self.profile = profile
        if session:
            self.session = session
        else:
            self.session = boto3.Session(profile_name=profile, region_name=region)
        self.account_id = None
        try:
            self._initialize_clients()
            self.account_id = self.session.client('sts').get_caller_identity()['Account']
        except Exception as e:
            logger.error(f"AWS init failed: {str(e)}")
            raise

    def _initialize_clients(self):
        self.lambda_client = self.session.client('lambda')
        self.ec2_client = self.session.client('ec2')
        self.rds_client = self.session.client('rds')
        self.s3_client = self.session.client('s3')
        self.sqs_client = self.session.client('sqs')
        self.iam_client = self.session.client('iam')
        self.ssm_client = self.session.client('ssm')

    def authenticate(self) -> bool:
        try:
            self.session.client('sts').get_caller_identity()
            return True
        except Exception:
            return False

    def scan_resources(self) -> List[CloudResource]:
        resources = []
        methods = [self._scan_ec2_instances, self._scan_lambda_functions,
                   self._scan_rds_instances, self._scan_s3_buckets,
                   self._scan_sqs_queues, self._scan_iam_roles]
        for method in methods:
            try:
                resources.extend(method())
            except Exception as e:
                logger.error(f"Scan error: {str(e)}")
        return resources

    def _scan_ec2_instances(self) -> List[CloudResource]:
        resources = []
        try:
            paginator = self.ec2_client.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        packages = self._get_ec2_packages(instance['InstanceId'])
                        resource = CloudResource(
                            id=instance['InstanceId'],
                            name=self._get_name_from_tags(instance.get('Tags', [])),
                            provider=CloudProvider.AWS,
                            type=ResourceType.COMPUTE,
                            region=self.region,
                            properties={
                                'instance_type': instance['InstanceType'],
                                'state': instance['State']['Name'],
                                'vpc_id': instance.get('VpcId'),
                                'public_ip': instance.get('PublicIpAddress'),
                                'platform': instance.get('Platform', 'linux'),
                                'packages': packages
                            },
                            tags=self._convert_tags(instance.get('Tags', [])),
                            created_at=instance.get('LaunchTime')
                        )
                        resources.append(resource)
        except Exception as e:
            logger.error(f"EC2 scan error: {str(e)}")
        return resources

    def _get_ec2_packages(self, instance_id: str) -> Dict:
        try:
            response = self.ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={
                    'commands': [
                        'dpkg-query -W -f=\'${Package} ${Version}\\n\'',
                        'rpm -qa --queryformat "%{NAME} %{VERSION}-%{RELEASE}\\n"'
                    ]
                }
            )
            command_id = response['Command']['CommandId']
            time.sleep(5)
            output = self.ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            return self._parse_package_output(output['StandardOutputContent'])
        except Exception as e:
            logger.error(f"EC2 package scan error: {str(e)}")
            return {}

    def _parse_package_output(self, content: str) -> Dict:
        packages = {}
        for line in content.split('\n'):
            if line.strip() and ' ' in line:
                pkg, version = line.strip().split(' ', 1)
                packages[pkg] = version
        return packages

    def _scan_lambda_functions(self) -> List[CloudResource]:
        resources = []
        try:
            paginator = self.lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for func in page['Functions']:
                    function_config = self.lambda_client.get_function_configuration(
                        FunctionName=func['FunctionName']
                    )
                    layers = func.get('Layers', [])
                    layer_packages = {}
                    for layer in layers:
                        layer_packages.update(self._get_layer_dependencies(layer['Arn']))
                    resource = CloudResource(
                        id=func['FunctionArn'],
                        name=func['FunctionName'],
                        provider=CloudProvider.AWS,
                        type=ResourceType.SERVERLESS,
                        region=self.region,
                        properties={
                            'runtime': function_config.get('Runtime', 'unknown'),
                            'memory': function_config.get('MemorySize', 0),
                            'timeout': function_config.get('Timeout', 0),
                            'handler': function_config.get('Handler', ''),
                            'last_modified': function_config.get('LastModified', ''),
                            'environment': function_config.get('Environment', {}),
                            'layers': layers,
                            'architecture': function_config.get('Architectures', ['x86_64'])[0],
                            'layer_packages': layer_packages
                        }
                    )
                    resources.append(resource)
        except Exception as e:
            logger.error(f"Lambda scan error: {str(e)}")
        return resources

    def _get_layer_dependencies(self, layer_arn: str) -> Dict:
        try:
            layer_info = self.lambda_client.get_layer_version(
                LayerName=layer_arn.split(':')[6],
                VersionNumber=int(layer_arn.split(':')[7])
            )
            return self._parse_layer_packages(layer_info['Content']['Location'])
        except Exception as e:
            logger.error(f"Layer scan error: {str(e)}")
            return {}

    def _parse_layer_packages(self, s3_url: str) -> Dict:
        packages = {}
        try:
            s3 = self.session.client('s3')
            bucket = s3_url.split('/')[2].split('.')[0]
            key = '/'.join(s3_url.split('/')[3:])
            with tempfile.TemporaryFile() as f:
                s3.download_fileobj(bucket, key, f)
                f.seek(0)
                with zipfile.ZipFile(f) as z:
                    if 'requirements.txt' in z.namelist():
                        with z.open('requirements.txt') as reqs:
                            for line in reqs.read().decode().split('\n'):
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    parts = line.split('==')
                                    if len(parts) == 2:
                                        packages[parts[0]] = parts[1]
        except Exception as e:
            logger.error(f"Package parsing error: {str(e)}")
        return packages

    def _scan_iam_roles(self) -> List[CloudResource]:
        resources = []
        try:
            paginator = self.iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    resources.append(CloudResource(
                        id=role['Arn'],
                        name=role['RoleName'],
                        provider=CloudProvider.AWS,
                        type=ResourceType.IDENTITY,
                        region=self.region,
                        properties={
                            'assume_role_policy': role['AssumeRolePolicyDocument'],
                            'created_at': role['CreateDate'].isoformat()
                        }
                    ))
        except Exception as e:
            logger.error(f"IAM scan error: {str(e)}")
        return resources

    def _scan_rds_instances(self) -> List[CloudResource]:
        resources = []
        try:
            paginator = self.rds_client.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for db_instance in page['DBInstances']:
                    resources.append(CloudResource(
                        id=db_instance['DBInstanceArn'],
                        name=db_instance['DBInstanceIdentifier'],
                        provider=CloudProvider.AWS,
                        type=ResourceType.DATABASE,
                        region=self.region,
                        properties={
                            'engine': db_instance['Engine'],
                            'instance_class': db_instance['DBInstanceClass'],
                            'status': db_instance['DBInstanceStatus']
                        }
                    ))
        except Exception as e:
            logger.error(f"RDS scan error: {str(e)}")
        return resources

    def _scan_s3_buckets(self) -> List[CloudResource]:
        resources = []
        try:
            response = self.s3_client.list_buckets()
            for bucket in response['Buckets']:
                resources.append(CloudResource(
                    id=f"arn:aws:s3:::{bucket['Name']}",
                    name=bucket['Name'],
                    provider=CloudProvider.AWS,
                    type=ResourceType.STORAGE,
                    region=self.region,
                    properties={'creation_date': bucket['CreationDate'].isoformat()}
                ))
        except Exception as e:
            logger.error(f"S3 scan error: {str(e)}")
        return resources

    def _scan_sqs_queues(self) -> List[CloudResource]:
        resources = []
        try:
            response = self.sqs_client.list_queues()
            if "QueueUrls" in response:
                for queue_url in response["QueueUrls"]:
                    resources.append(CloudResource(
                        id=queue_url,
                        name=queue_url.split('/')[-1],
                        provider=CloudProvider.AWS,
                        type=ResourceType.QUEUE,
                        region=self.region,
                        properties={}
                    ))
        except Exception as e:
            logger.error(f"SQS scan error: {str(e)}")
        return resources

    def get_dependencies(self, resource: CloudResource) -> Set[str]:
        dependencies = set()
        try:
            if resource.type == ResourceType.COMPUTE:
                dependencies.update(self._get_ec2_dependencies(resource.id))
            elif resource.type == ResourceType.SERVERLESS:
                dependencies.update(self._get_lambda_dependencies(resource.id))
            elif resource.type == ResourceType.IDENTITY:
                dependencies.update(self._get_iam_role_dependencies(resource.name))
            if resource.type == ResourceType.IDENTITY:
                dependencies.update(self._get_dependent_resources(resource))
        except Exception as e:
            logger.error(f"Dependency error: {str(e)}")
        return dependencies

    def _get_dependent_resources(self, resource: CloudResource) -> Set[str]:
        deps = set()
        try:
            if resource.type == ResourceType.IDENTITY:
                lambda_paginator = self.lambda_client.get_paginator('list_functions')
                for page in lambda_paginator.paginate():
                    for func in page['Functions']:
                        if func.get('Role') == resource.id:
                            deps.add(func['FunctionArn'])
                ec2_paginator = self.ec2_client.get_paginator('describe_instances')
                for page in ec2_paginator.paginate():
                    for reservation in page['Reservations']:
                        for instance in reservation['Instances']:
                            if instance.get('IamInstanceProfile', {}).get('Arn', '').startswith(resource.id):
                                deps.add(instance['InstanceId'])
        except Exception as e:
            logger.error(f"Reverse dependency lookup error: {str(e)}")
        return deps

    def _get_name_from_tags(self, tags: List[Dict]) -> str:
        for tag in tags:
            if tag['Key'].lower() == 'name':
                return tag['Value']
        return 'unnamed'

    def _convert_tags(self, aws_tags: List[Dict]) -> Dict:
        return {tag['Key']: tag['Value'] for tag in aws_tags}

class DependencyVisualizer:
    def __init__(self):
        self.graph = nx.DiGraph()
        
    def create_graph(self, dependencies: Dict) -> None:
        self.graph.clear()
        for resource_id, info in dependencies.items():
            resource = info['resource']
            self.graph.add_node(resource.name, 
                                type=resource.type.value,
                                provider=resource.provider.value)
        for resource_id, info in dependencies.items():
            resource = info['resource']
            for dep in info.get('dependencies', []):
                if dep['name'] in self.graph:
                    self.graph.add_edge(resource.name, dep['name'])
    
    def detect_bottlenecks(self):
        bottlenecks = []
        try:
            for node in self.graph.nodes():
                in_degree = self.graph.in_degree(node)
                if in_degree >= 2 or 'ServiceRole' in node:
                    bottlenecks.append({
                        'resource': node,
                        'type': 'Single Point of Failure' if in_degree >=2 else 'AWS Service Role',
                        'dependents': list(self.graph.predecessors(node)),
                        'severity': 'High' if in_degree > 3 else 'Medium'
                    })
            
            try:
                cycles = list(nx.simple_cycles(self.graph))
                if cycles:
                    bottlenecks.append({
                        'type': 'Circular Dependency',
                        'chain': cycles[0],
                        'severity': 'Critical'
                    })
            except nx.NetworkXNoCycle:
                pass
        except Exception as e:
            logger.error(f"Bottleneck detection failed: {str(e)}")
        return bottlenecks

    def visualize(self, output_path: str = 'dependency_graph.png') -> None:
        if not self.graph.nodes():
            logger.warning("No nodes in graph to visualize")
            return
        plt.figure(figsize=(15, 10))
        colors = {
            'compute': '#ADD8E6',
            'serverless': '#90EE90',
            'identity': '#FFB6C1',
            'storage': '#FFE4B5',
            'database': '#DDA0DD'
        }
        node_colors = [colors.get(self.graph.nodes[node]['type'].lower(), '#D3D3D3') 
                      for node in self.graph.nodes()]
        pos = nx.spring_layout(self.graph, k=2, iterations=50)
        nx.draw(self.graph, pos,
                node_color=node_colors,
                node_size=3000,
                font_size=10,
                font_weight='bold',
                arrows=True,
                edge_color='gray',
                arrowsize=20,
                with_labels=True)
        legend_elements = [plt.Line2D([0], [0], marker='o', color='w',
                                    markerfacecolor=color, label=res_type.title(),
                                    markersize=10)
                         for res_type, color in colors.items()]
        plt.legend(handles=legend_elements,
                  loc='center left',
                  bbox_to_anchor=(1, 0.5))
        plt.tight_layout()
        plt.savefig(output_path, 
                   bbox_inches='tight',
                   dpi=300,
                   pad_inches=0.5)
        plt.close()

class MultiCloudScanner:
    def __init__(self):
        self.scanners: Dict[CloudProvider, CloudScanner] = {}
        
    def add_scanner(self, provider: CloudProvider, scanner: CloudScanner):
        self.scanners[provider] = scanner
        
    def scan_all(self) -> Dict[CloudProvider, List[CloudResource]]:
        results = {}
        for provider, scanner in self.scanners.items():
            if scanner.authenticate():
                results[provider] = scanner.scan_resources()
        return results
    
    def analyze_dependencies(self, resources: Dict[CloudProvider, List[CloudResource]]) -> Dict:
        all_resources = {r.id: r for provider_resources in resources.values() for r in provider_resources}
        id_map = {}
        for res in all_resources.values():
            if res.type == ResourceType.IDENTITY:
                id_map[f"arn:aws:iam::{res.properties.get('account_id')}:role/{res.name}"] = res.id
            elif res.type == ResourceType.NETWORK:
                id_map[res.properties.get('vpc_id')] = res.id

        dependencies = {}
        for resource in all_resources.values():
            try:
                raw_deps = self.scanners[resource.provider].get_dependencies(resource)
                resolved_deps = [self._resolve_dependency(dep_id, id_map, all_resources) for dep_id in raw_deps]
                dependencies[resource.id] = {
                    'resource': resource,
                    'dependencies': [{
                        'id': dep_id,
                        'name': all_resources[dep_id].name if dep_id in all_resources else dep_id,
                        'type': all_resources[dep_id].type if dep_id in all_resources else 'External'
                    } for dep_id in resolved_deps if dep_id]
                }
            except Exception as e:
                logger.error(f"Dependency error: {str(e)}")
        return dependencies

    def _resolve_dependency(self, dep_id: str, id_map: Dict, all_resources: Dict) -> Optional[str]:
        if dep_id in id_map:
            return id_map[dep_id]
        if dep_id.startswith('arn:aws:iam::'):
            role_name = dep_id.split('/')[-1]
            return next((rid for rid, res in all_resources.items() 
                        if res.type == ResourceType.IDENTITY and res.name == role_name), None)
        if 'sg-' in dep_id:
            return next((rid for rid, res in all_resources.items()
                        if res.type == ResourceType.NETWORK and dep_id in res.properties.get('security_groups', [])), None)
        return dep_id

class VulnerabilityAnalyzer:
    def __init__(self):
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.delay = 10
        self.api_counter = 0

    def check_vulnerabilities(self, resource: CloudResource) -> List[dict]:
        search_terms = self._get_search_terms(resource)
        if not search_terms:
            logger.info(f"No search terms available for {resource.name}")
            return []

        try:
            logger.info(f"🔍 Scanning {resource.name} against NVD...")
            print(f"  Querying NVD for: {', '.join(search_terms)}")
            time.sleep(self.delay)
            keyword_str = " OR ".join(f'"{term}"' for term in search_terms)
            params = {'keywordSearch': keyword_str, 'resultsPerPage': 5}
            response = requests.get(self.nvd_url, params=params, timeout=15)
            self.api_counter += 1
            if response.status_code == 429:
                logger.warning("⚠️ NVD Rate Limit Hit! Delaying...")
                time.sleep(30)
                return []
            data = response.json()
            vulns = self._process_nvd_response(data, resource)
            print(f"  Found {len(vulns)} relevant CVEs")
            return vulns
        except Exception as e:
            logger.error(f"NVD scan failed: {str(e)}")
            return []

    def _process_nvd_response(self, data: dict, resource: CloudResource) -> List[dict]:
        vulns = []
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            if self._is_relevant(cve, resource):
                vulns.append(self._format_vuln(cve))
        return sorted(vulns, key=lambda x: x['cvss_score'], reverse=True)[:3]

    def _is_relevant(self, cve: dict, resource: CloudResource) -> bool:
        return True

    def _format_vuln(self, cve: dict) -> dict:
        metrics = cve.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
        if not cvss_v3:
            cvss_v3 = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {})
        descriptions = cve.get('descriptions', [])
        description = next((d['value'] for d in descriptions if d['lang'] == 'en'), 'No description available')
        return {
            'id': cve.get('id', 'Unknown'),
            'description': description[:200] + '...',
            'cvss_score': cvss_v3.get('baseScore', 0.0),
            'severity': cvss_v3.get('baseSeverity', 'UNKNOWN'),
            'published': cve.get('published'),
            'vector': cvss_v3.get('vectorString', 'N/A')
        }

    def _get_search_terms(self, resource: CloudResource) -> List[str]:
        terms = []
        if resource.type == ResourceType.SERVERLESS:
            terms.extend(self._get_lambda_terms(resource))
        elif resource.type == ResourceType.COMPUTE:
            terms.extend(self._get_ec2_terms(resource))
        return terms

    def _get_lambda_terms(self, resource: CloudResource) -> List[str]:
        terms = []
        runtime = resource.properties.get('runtime', '')
        if 'python' in runtime.lower():
            py_version = runtime.replace('Python', '').strip()
            terms.extend([f"Python {py_version}", f"CPython {py_version}"])
        if 'layer_packages' in resource.properties:
            terms.extend([f"{pkg} {ver}" for pkg, ver in resource.properties['layer_packages'].items()])
        return terms

    def _get_ec2_terms(self, resource: CloudResource) -> List[str]:
        terms = []
        if 'packages' in resource.properties:
            terms.extend([f"{pkg} {ver}" for pkg, ver in resource.properties['packages'].items()])
        return terms

class RiskPredictor:
    def __init__(self):
        self.risk_weights = {
            'vulnerability': 0.4,
            'dependencies': 0.2,
            'exposure': 0.2,
            'configuration': 0.15,
            'bottleneck': 0.05
        }

    def predict_risk(self, resource: CloudResource, vulns: List[dict], dependencies: List, bottleneck_score: float) -> float:
        vuln_component = max((v['cvss_score']/10 * self.risk_weights['vulnerability'] for v in vulns), default=0)
        dep_risk = min(len(dependencies)/10 * self.risk_weights['dependencies'], self.risk_weights['dependencies'])
        exposure_risk = self._calculate_exposure_risk(resource) * self.risk_weights['exposure']
        config_risk = self._calculate_configuration_risk(resource) * self.risk_weights['configuration']
        bottleneck_risk = bottleneck_score * self.risk_weights['bottleneck']
        return min(vuln_component + dep_risk + exposure_risk + config_risk + bottleneck_risk, 1.0)

    def _calculate_exposure_risk(self, resource: CloudResource) -> float:
        if resource.type == ResourceType.SERVERLESS:
            env_vars = resource.properties.get('environment', {}).get('Variables', {})
            has_secrets = any(k.lower() in v.lower() for k, v in env_vars.items() for secret_word in ['key', 'secret', 'password', 'token'])
            return 0.7 if has_secrets else 0.3
        elif resource.type == ResourceType.IDENTITY:
            policy = str(resource.properties.get('assume_role_policy', ''))
            return 0.8 if '"Effect": "Allow"' in policy and '"Principal": "*"' in policy else 0.4
        return 0.5

    def _calculate_configuration_risk(self, resource: CloudResource) -> float:
        if resource.type == ResourceType.SERVERLESS:
            runtime = resource.properties.get('runtime', '').lower()
            outdated_runtimes = ['python3.6', 'nodejs12', 'nodejs10']
            if any(old_runtime in runtime for old_runtime in outdated_runtimes):
                return 1.0
            timeout = resource.properties.get('timeout', 0)
            memory = resource.properties.get('memory', 0)
            if timeout > 300 or memory > 1024:
                return 0.7
        return 0.3

class RemediationEngine:
    REMEDIATION_ACTIONS = {
        'lambda_runtime_update': {
            'condition': lambda r: hasattr(r, 'type') and r.type == ResourceType.SERVERLESS and 'EOL' in r.properties.get('runtime', ''),
            'action': lambda r: f"Update Lambda {r.name} runtime to latest LTS version"
        },
        's3_bucket_encryption': {
            'condition': lambda r: hasattr(r, 'type') and r.type == ResourceType.STORAGE and not r.properties.get('encryption'),
            'action': lambda r: f"Enable AES-256 encryption on S3 bucket {r.name}"
        },
        'iam_least_privilege': {
            'condition': lambda r: hasattr(r, 'type') and r.type == ResourceType.IDENTITY and 'AdministratorAccess' in str(r.properties),
            'action': lambda r: f"Apply least-privilege policy to IAM role {r.name}"
        },
        'bottleneck_redundancy': {
            'condition': lambda r: isinstance(r, dict) and r.get('type') == 'Single Point of Failure',
            'action': lambda r: (f"Implement redundancy for {r['resource']}\n" 
                                 f"Dependents: {len(r.get('dependents', []))} resources\n"
                                 "• Create failover mechanisms\n"
                                 "• Add load balancing")
        },
        'service_role_review': {
            'condition': lambda r: isinstance(r, dict) and r.get('type') == 'AWS Service Role',
            'action': lambda r: (f"Review AWS service role: {r['resource']}\n"
                                 "• Check cross-account access\n"
                                 "• Audit permissions scope\n"
                                 "• Review attached policies\n"
                                 "• Implement role session duration limits")
        },
        'circular_dependency': {
            'condition': lambda r: isinstance(r, dict) and r.get('type') == 'Circular Dependency',
            'action': lambda r: (f"Break circular dependency chain: {' → '.join(r['chain'])}\n"
                                 "• Implement dependency inversion\n"
                                 "• Consider event-driven architecture\n"
                                 "• Review IAM role relationships\n"
                                 "• Document dependency changes")
        },
        'outdated_package': {
            'condition': lambda r: (hasattr(r, 'properties') and ('packages' in r.properties or 'layer_packages' in r.properties)),
            'action': lambda r: RemediationEngine._package_remediation(r)
        }
    }

    def _package_remediation(self, resource: CloudResource) -> str:
        remediations = []
        if 'packages' in resource.properties:
            for pkg, ver in resource.properties['packages'].items():
                remediations.append(f"Update {pkg} from {ver} to latest secure version")
        if 'layer_packages' in resource.properties:
            for pkg, ver in resource.properties['layer_packages'].items():
                remediations.append(f"Update layer package {pkg} from {ver} in Lambda layers")
        return '\n'.join(remediations)

    def generate_remediation(self, context):
        try:
            remediation_actions = []
            for action_config in self.REMEDIATION_ACTIONS.values():
                try:
                    if action_config['condition'](context):
                        remediation = action_config['action'](context)
                        if remediation:
                            if isinstance(remediation, list):
                                remediation_actions.extend(remediation)
                            else:
                                remediation_actions.append(remediation)
                except (KeyError, AttributeError, TypeError) as e:
                    logger.debug(f"Skipping remediation action: {str(e)}")
                    continue
            return remediation_actions
        except Exception as e:
            logger.error(f"Remediation generation error: {str(e)}")
            return []

def run_scan(session: boto3.Session) -> dict:
    output_json = {}

    scanner = MultiCloudScanner()
    try:
        aws_scanner = AWSScanner(region=session.region_name, session=session)
        scanner.add_scanner(CloudProvider.AWS, aws_scanner)
    except Exception as e:
        logger.error(f"AWS init failed: {str(e)}")
        output_json["error"] = f"AWS init failed: {str(e)}"
        return output_json

    results = scanner.scan_all()
    dependencies = scanner.analyze_dependencies(results)
    
    visualizer = DependencyVisualizer()
    try:
        visualizer.create_graph(dependencies)
        visualizer.visualize()  # Saves dependency_graph.png
        graph_msg = "Dependency graph has been saved as 'dependency_graph.png'"
        print(graph_msg)
        output_json["graph_info"] = graph_msg
    except Exception as e:
        graph_msg = f"Visualization error: {e}"
        logger.error(graph_msg)
        output_json["graph_info"] = graph_msg

    vuln_analyzer = VulnerabilityAnalyzer()
    risk_predictor = RiskPredictor()
    remediator = RemediationEngine()
    bottlenecks = visualizer.detect_bottlenecks() or []

    cs_report_lines = []
    cs_report_lines.append("=== Cloud Security Report ===")
    for provider, resources in results.items():
        cs_report_lines.append(f"\n{provider.value.upper()} RESOURCES:")
        for resource in resources:
            try:
                vulns = vuln_analyzer.check_vulnerabilities(resource)
                deps = dependencies.get(resource.id, {}).get('dependencies', [])
                risk_score = risk_predictor.predict_risk(resource, vulns, deps, 0.0)
                cs_report_lines.append(f"\n- {resource.name} ({resource.type.value})")
                cs_report_lines.append(f"  Risk Score: {risk_score:.2%}")
                if vulns:
                    cs_report_lines.append("  Vulnerabilities:")
                    for vuln in vulns:
                        cs_report_lines.append(f"    - {vuln['id']} ({vuln['severity']}) [CVSS: {vuln['cvss_score']}]")
                        cs_report_lines.append(f"      {vuln['description'][:100]}...")
            except Exception as e:
                error_msg = f"Error processing resource {resource.name}: {str(e)}"
                logger.error(error_msg)
                cs_report_lines.append(error_msg)
                continue
    output_json["cloud_security_report"] = "\n".join(cs_report_lines)

    bottleneck_lines = []
    bottleneck_lines.append("=== Bottleneck Analysis ===")
    if bottlenecks:
        for bn in bottlenecks:
            bottleneck_lines.append(f"\n🚨 {bn['type']} ({bn['severity']})")
            if bn['type'] in ['Single Point of Failure', 'AWS Service Role']:
                bottleneck_lines.append(f"- Resource: {bn['resource']}")
                bottleneck_lines.append(f"- Dependents: {len(bn['dependents'])} resources")
            elif bn['type'] == 'Circular Dependency':
                bottleneck_lines.append(f"- Dependency Chain: {' → '.join(bn['chain'])}")
    else:
        bottleneck_lines.append("No critical bottlenecks detected")
    output_json["bottleneck_analysis"] = "\n".join(bottleneck_lines)

    rec_lines = []
    rec_lines.append("=== Actionable Recommendations ===")
    for bn in bottlenecks:
        rec_lines.append(f"\n🔧 For {bn['type']}:")
        recs = remediator.generate_remediation(bn)
        rec_lines.append("\n".join(recs))
    output_json["actionable_recommendations"] = "\n".join(rec_lines)

    dep_map_lines = []
    dep_map_lines.append("DEPENDENCY MAP:")
    for resource_id, info in dependencies.items():
        resource = info['resource']
        dep_map_lines.append(f"\n{resource.name} ({resource.provider.value}):")
        deps = info.get('dependencies', [])
        if deps:
            for dep in deps:
                dep_map_lines.append(f"- Depends on: {dep['name']} ({dep['type']})")
        else:
            dep_map_lines.append("- No dependencies found")
    output_json["dependency_map"] = "\n".join(dep_map_lines)

    return output_json

if __name__ == "__main__":
    # For testing locally, create a boto3 session using default credentials.
    session = boto3.Session()
    report = run_scan(session)
    print(json.dumps(report, indent=2))
