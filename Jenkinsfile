pipeline {
    agent any

    options {
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    parameters {
        string(
            name: 'IMAGE_TO_SCAN',
            defaultValue: 'alpine:3.24',
            description: 'Container image reference to scan with Trivy'
        )
    }

    stages {
        stage('Check tools') {
            steps {
                sh 'python3 --version'
                sh 'trivy --version'
            }
        }

        stage('Install AegisTrail') {
            steps {
                sh 'python3 -m pip install -e ".[dev]"'
            }
        }

        stage('Lint and test') {
            steps {
                sh 'ruff check .'
                sh 'pytest'
            }
        }

        stage('Scan container image') {
            steps {
                sh 'mkdir -p artifacts'
                sh 'python3 -m aegistrail scan --image "$IMAGE_TO_SCAN" --policy policy.toml --out-dir artifacts'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'artifacts/**', allowEmptyArchive: true
        }
        success {
            echo 'AegisTrail tests and image policy gate passed.'
        }
        failure {
            echo 'Build failed. Review the test output or the AegisTrail policy report in archived artifacts.'
        }
    }
}
