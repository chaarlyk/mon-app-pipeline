pipeline {
    agent {
        dockerfile {
            dir 'agent'
            args '-v /var/run/docker.sock:/var/run/docker.sock'
        }
    }

    environment {
        SONAR_TOKEN = credentials('sonarqube-token')
    }

    stages {
        stage('Build') {
            steps {
                sh 'npm install'
            }
        }

        stage('Analyse SonarQube (SAST & SCA)') {
            steps {
                // La seule modification est l'ajout de ce wrapper
                withSonarQubeEnv('SonarQube') {
                    script {
                        // Le nom du réseau est basé sur le nom du dossier de votre projet 
                        docker.image('sonarsource/sonar-scanner-cli').inside('--network mon-app-pipeline_default') {
                            sh """
                               sonar-scanner \\
                               -Dsonar.host.url=http://sonarqube:9000 \\
                               -Dsonar.token=${SONAR_TOKEN}
                            """
                        }
                    }
                }
            }
        }

        stage('Vérification du Quality Gate') {
            steps {
                timeout(time: 15, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('Build & Scan Image Docker') {
            steps {
                script {
                    def imageName = "votre-user/mon-app-node:${env.BUILD_NUMBER}"
                    def customImage = docker.build(imageName)

                    sh "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --exit-code 1 --severity HIGH,CRITICAL ${imageName}"
                }
            }
        }
    }
}
