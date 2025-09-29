pipeline {
  agent any
  triggers {
    githubPush()
    pollSCM('H H * * *')
  }
  environment {
    MAIL_RECIPIENTS = 'dev+tests-reports@wazo.community'
  }
  options {
    skipStagesAfterUnstable()
    timestamps()
    buildDiscarder(logRotator(numToKeepStr: '10'))
  }
  stages {
    stage('Debian build and deploy') {
      steps {
        build job: 'build-package-no-arch', parameters: [
          string(name: 'PACKAGE', value: "wazo-auth"),
          string(name: "BRANCH", value: "bookworm"),
          string(name: "DISTRIBUTION", value: "wazo-dev-bookworm"),
        ]
      }
    }
    stage('Docker build') {
      steps {
        sh "sed -i s/master.zip/bookworm.zip/ requirements.txt"
        sh "docker build --no-cache -t wazoplatform/wazo-auth:bookworm ."
      }
    }
    stage('Docker publish') {
      steps {
        sh "docker push wazoplatform/wazo-auth:bookworm"
      }
    }
    stage('Docker build DB') {
      steps {
        sh "sed -i s/master.zip/bookworm.zip/ requirements.txt"
        sh "docker build -t wazoplatform/wazo-auth-db:bookworm -f contribs/docker/Dockerfile-db ."
      }
    }
    stage('Docker publish DB') {
      steps {
        sh "docker push wazoplatform/wazo-auth-db:bookworm"
      }
    }
  }
  post {
    failure {
      emailext to: "${MAIL_RECIPIENTS}", subject: '${DEFAULT_SUBJECT}', body: '${DEFAULT_CONTENT}'
    }
    fixed {
      emailext to: "${MAIL_RECIPIENTS}", subject: '${DEFAULT_SUBJECT}', body: '${DEFAULT_CONTENT}'
    }
  }
}
