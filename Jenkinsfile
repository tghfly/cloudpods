pipeline {
    agent any

    parameters {
        choice(
            name: 'SERVICE',
            choices: [
                'all',
                'aiproxy',
                'ansibleserver',
                'apigateway',
                'apimap',
                'baremetal-agent',
                'climc',
                'cloudevent',
                'cloudid',
                'cloudir',
                'cloudmon',
                'cloudnet',
                'cloudproxy',
                'cloutpost',
                'devtool',
                'esxi-agent',
                'executor-server',
                'fetcherfs',
                'glance',
                'host',
                'host-deployer',
                'host-health',
                'host-image',
                'keystone',
                'lbagent',
                'logger',
                'mcp-server',
                'monitor',
                'notify',
                'region',
                'region-dns',
                's3gateway',
                'scheduledtask',
                'scheduler',
                'vpcagent',
                'webconsole',
                'yunionconf'
            ],
            description: '选择要构建的服务，选 all 则构建全部'
        )
        string(
            name: 'VERSION',
            defaultValue: 'v4.0.3',
            description: '镜像版本前缀'
        )
        string(
            name: 'REGISTRY',
            defaultValue: 'registry.tydic.com/yunionio',
            description: '镜像仓库地址'
        )
        string(
            name: 'BASE_IMAGE',
            defaultValue: '',
            description: '基础镜像（留空则自动使用 REGISTRY/SERVICE:VERSION）'
        )
    }

    environment {
        OUTPUT_DIR  = "_output/bin"
        GOROOT      = "/usr/local/go"
        PATH        = "${GOROOT}/bin:${env.PATH}"
    }

    stages {
        stage('Build & Push') {
            steps {
                script {
                    env.TAG = "${params.VERSION}-" + sh(script: 'date +%Y%m%d%H%M', returnStdout: true).trim()

                    def services = []
                    if (params.SERVICE == 'all') {
                        services = [
                            'aiproxy', 'ansibleserver', 'apigateway', 'apimap',
                            'baremetal-agent', 'climc', 'cloudevent', 'cloudid',
                            'cloudir', 'cloudmon', 'cloudnet', 'cloudproxy',
                            'cloutpost', 'devtool', 'esxi-agent', 'executor-server',
                            'fetcherfs', 'glance', 'host', 'host-deployer',
                            'host-health', 'host-image', 'keystone', 'lbagent',
                            'logger', 'mcp-server', 'monitor', 'notify',
                            'region', 'region-dns', 's3gateway', 'scheduledtask',
                            'scheduler', 'vpcagent', 'webconsole', 'yunionconf'
                        ]
                    } else {
                        services = [params.SERVICE]
                    }

                    for (svc in services) {
                        stage("${svc}") {
                            buildAndPush(svc)
                        }
                    }
                }
            }
        }
    }

    post {
        success {
            echo "构建完成: ${params.SERVICE}, 镜像TAG: ${env.TAG}"
        }
        failure {
            echo "构建失败: ${params.SERVICE}"
        }
    }
}

def buildAndPush(String service) {
    def image = "${params.REGISTRY}/${service}:${env.TAG}"
    def baseImage = params.BASE_IMAGE ?: "${params.REGISTRY}/${service}:${params.VERSION}"

    sh "CGO_ENABLED=0 go build -mod vendor -o ${env.OUTPUT_DIR}/${service} ./cmd/${service}"

    sh """
        docker build --no-cache \
            --build-arg BASE_IMAGE=${baseImage} \
            --build-arg SERVICE=${service} \
            -t ${image} \
            -f Dockerfile ${env.OUTPUT_DIR}
        docker push ${image}
    """

    echo "✅ ${service} -> ${image}"
}
