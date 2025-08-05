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
                withSonarQubeEnv('SonarQube') {
                    script {
                        docker.image('sonarsource/sonar-scanner-cli').inside('--network mon-app-pipeline_default') {
                            sh """
                               sonar-scanner \\
                               -Dsonar.host.url=http://sonarqube:9000 \\
                               -Dsonar.token=${SONAR_TOKEN} \\
                               -Dsonar.qualitygate.wait=true \\
                               -Dsonar.qualitygate.timeout=300
                            """
                        }
                    }
                }
            }
        }

        stage('Vérification du Quality Gate') {
            steps {
                timeout(time: 15, unit: 'MINUTES') {
                    script {
                        def qg = waitForQualityGate()
                        echo "Quality Gate Status: ${qg.status}"
                        
                        if (qg.status != 'OK') {
                            error "Pipeline aborted due to quality gate failure: ${qg.status}"
                        }
                        
                        // Vérification supplémentaire des Security Hotspots
                        echo "Vérification des Security Hotspots..."
                        sh """
                            # Récupérer les métriques de sécurité via l'API SonarQube
                            SECURITY_HOTSPOTS=\$(curl -s -u ${SONAR_TOKEN}: \\
                                "http://sonarqube:9000/api/measures/component?component=mon-app-pipeline-securise&metricKeys=security_hotspots" \\
                                | grep -o '"value":"[^"]*"' | grep -o '[0-9]*' || echo "0")
                            
                            VULNERABILITIES=\$(curl -s -u ${SONAR_TOKEN}: \\
                                "http://sonarqube:9000/api/measures/component?component=mon-app-pipeline-securise&metricKeys=vulnerabilities" \\
                                | grep -o '"value":"[^"]*"' | grep -o '[0-9]*' || echo "0")
                            
                            echo "Security Hotspots trouvés: \$SECURITY_HOTSPOTS"
                            echo "Vulnérabilités trouvées: \$VULNERABILITIES"
                            
                            if [ "\$SECURITY_HOTSPOTS" -gt "0" ]; then
                                echo "❌ ÉCHEC: \$SECURITY_HOTSPOTS Security Hotspot(s) détecté(s)"
                                echo "Veuillez consulter: http://sonarqube:9000/security_hotspots?id=mon-app-pipeline-securise"
                                exit 1
                            fi
                            
                            if [ "\$VULNERABILITIES" -gt "0" ]; then
                                echo "❌ ÉCHEC: \$VULNERABILITIES vulnérabilité(s) détectée(s)"
                                exit 1
                            fi
                            
                            echo "✅ Aucun problème de sécurité détecté"
                        """
                    }
                }
            }
        }

        stage('Build & Scan Image Docker') {
            steps {
                script {
                    def imageName = "votre-user/mon-app-node:${env.BUILD_NUMBER}"
                    def customImage = docker.build(imageName)

                    echo "Scanning Docker image for vulnerabilities..."
                    sh "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --exit-code 1 --severity HIGH,CRITICAL ${imageName}"
                }
            }
        }
    }

    post {
        always {
            // Nettoyage
            sh 'docker system prune -f || true'
        }
        
        failure {
            echo '❌ Pipeline échoué en raison de problèmes de sécurité ou de qualité'
            echo 'Consultez les rapports SonarQube et Trivy pour plus de détails'
        }
        
        success {
            echo '✅ Pipeline réussi - Tous les contrôles de sécurité et de qualité sont passés'
        }
    }
}