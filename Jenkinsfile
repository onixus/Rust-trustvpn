// Native macOS/Windows CI consumes one frozen client source snapshot.
pipeline {
  agent none
  options { disableConcurrentBuilds(); timestamps(); timeout(time: 120, unit: 'MINUTES'); buildDiscarder(logRotator(numToKeepStr: '15')) }
  parameters { booleanParam(name: 'RUN_WINDOWS', defaultValue: true, description: 'Explicitly defer Windows when its node is offline'); booleanParam(name: 'RUN_LINUX', defaultValue: true, description: 'Run additional Linux ARM checks; x86 Linux has an independent pipeline'); booleanParam(name: 'WINDOWS_SYSTEM_E2E', defaultValue: false, description: 'Run invasive installer/Wintun tests only on an idle Windows test host without a user installation'); choice(name: 'WINDOWS_TRANSPORT', choices: ['trusttunnel', 'http3'], description: 'TrustTunnel transport of the Wintun service E2E: HTTP/2 (trusttunnel) or HTTP/3') }
  stages {
    stage('Source snapshot') {
      agent { label 'built-in' }
      steps {
        deleteDir()
        sh 'python3 /Users/onixus/Git/R-Trusttunnel/ci/snapshot.py .'
        stash name: 'source', includes: '**', useDefaultExcludes: false
        archiveArtifacts artifacts: 'source-manifest.json,Jenkinsfile', fingerprint: true
      }
    }
    stage('Gitleaks + Trivy') {
      agent { label 'built-in' }
      steps { sh 'RTRUST_TOOL_CACHE="$JENKINS_HOME/caches/rtrust-native-tools" python3 ci/run.py security python3 ci/security.py' }
      post { always { junit 'reports/security.xml'; archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true } }
    }
    stage('Native platforms') {
      parallel {
        stage('macOS unit / build / smoke') {
          agent { label 'macos-arm64' }
          steps {
            sh "find . -mindepth 1 -maxdepth 1 ! -name target ! -name .ci-tools -exec rm -rf {} +"
            unstash 'source'
            sh '''export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"
              rustup toolchain install 1.98.1 --profile minimal --component clippy,rustfmt
              export RUSTUP_TOOLCHAIN=1.98.1
              python3 ci/run.py macos-fmt cargo fmt --all --check
              python3 ci/run.py macos-unit cargo test --workspace --locked --quiet
              python3 ci/run.py macos-keyring cargo test -p rtrust-store --locked os_keyring_restart_roundtrip -- --ignored --exact tests::os_keyring_restart_roundtrip
              python3 ci/run.py macos-h2 cargo test --manifest-path vendor/h2/Cargo.toml --lib --locked --quiet -- --skip hpack::test::fixture
              python3 ci/run.py macos-clippy cargo clippy --workspace --all-targets --locked -- -D warnings
              python3 ci/run.py macos-build cargo build --release -p rtrust-webview -p rtrust-native -p rtrust-inspect -p rtrust-tun --locked
              python3 ci/run.py macos-smoke python3 ci/smoke.py
              python3 ci/run.py macos-webview python3 ci/webview_smoke.py
              python3 ci/run.py macos-hysteria python3 ci/hysteria_interop.py
              python3 ci/run.py macos-amneziawg python3 ci/amneziawg_interop.py
              python3 scripts/package-preview.py
              python3 ci/run.py macos-dmg python3 scripts/package-macos-dmg.py
              python3 ci/run.py macos-system-package python3 scripts/package-macos-system.py
              python3 ci/run.py macos-bundled-package python3 scripts/package-macos-system.py --bundled-service
              python3 ci/run.py macos-ui-choices python3 scripts/package-macos-ui-choices.py --binary-dir target/release
            '''
            stash name: 'macos-bins', includes: 'target/release/rtrust-inspect'
          }
          post { always { junit allowEmptyResults: true, testResults: 'reports/macos-*.xml'; archiveArtifacts artifacts: 'reports/macos-*,dist/native-preview-darwin/**,dist/R-TrustTunnel-macOS-*.dmg*,dist/R-TrustTunnel-macOS-*.pkg*', allowEmptyArchive: true, fingerprint: true } }
        }
        stage('Windows unit / build / smoke') {
          when { beforeAgent true; expression { params.RUN_WINDOWS } }
          agent { label 'windows-amd64' }
          steps {
            powershell "Get-ChildItem -Force | Where-Object { \$_.Name -notin @('target','.ci-tools') } | Remove-Item -Recurse -Force"
            unstash 'source'
            powershell '''
              $ErrorActionPreference='Stop'
              $env:PATH="$env:USERPROFILE/.cargo/bin;$env:PATH"
              rustup toolchain install 1.98.1 --profile minimal --component clippy,rustfmt
              if ($LASTEXITCODE) { throw 'Rust toolchain install failed' }
              $env:RUSTUP_TOOLCHAIN='1.98.1'
              $env:RUSTFLAGS='-C target-feature=+crt-static'
              python ci/run.py windows-fmt cargo fmt --all --check
              if ($LASTEXITCODE) { throw 'Formatting failed' }
              python ci/run.py windows-unit cargo test --workspace --locked --quiet
              if ($LASTEXITCODE) { throw 'Unit failed' }
              python ci/run.py windows-keyring python ci/windows_desktop.py cargo test -p rtrust-store --locked os_keyring_restart_roundtrip -- --ignored --exact tests::os_keyring_restart_roundtrip
              if ($LASTEXITCODE) { throw 'Credential persistence failed' }
              python ci/run.py windows-h2 cargo test --manifest-path vendor/h2/Cargo.toml --lib --locked --quiet -- --skip hpack::test::fixture
              if ($LASTEXITCODE) { throw 'H2 failed' }
              python ci/run.py windows-clippy cargo clippy --workspace --all-targets --locked -- -D warnings
              if ($LASTEXITCODE) { throw 'Clippy failed' }
              python ci/run.py windows-build cargo build --release -p rtrust-webview -p rtrust-native -p rtrust-inspect -p rtrust-tun -p rtrust-update --locked
              if ($LASTEXITCODE) { throw 'Build failed' }
              python ci/run.py windows-smoke python ci/windows_desktop.py python ci/smoke.py
              if ($LASTEXITCODE) { throw 'Smoke failed' }
              python scripts/package-preview.py --ui both
              if ($LASTEXITCODE) { throw 'Packaging failed' }
              python ci/wintun.py
              if ($LASTEXITCODE) { throw 'Wintun packaging failed' }
              python ci/run.py windows-installer python ci/package_windows.py
              if ($LASTEXITCODE) { throw 'Installer packaging failed' }
              if ($env:WINDOWS_SYSTEM_E2E -eq 'true') {
                python ci/run.py windows-installer-e2e python ci/windows_installer_e2e.py
                if ($LASTEXITCODE) { throw 'Installer lifecycle failed' }
              } else {
                python ci/skip.py windows-installer-e2e 'System tests disabled; preserve installed user application'
                python ci/skip.py windows-service-e2e 'System tests disabled; preserve user network'
                python ci/skip.py windows-full-e2e 'System tests disabled; preserve user network'
              }
            '''
            stash name: 'windows-bins', includes: 'target/release/rtrust-inspect.exe'
          }
          post { always { junit allowEmptyResults: true, testResults: 'reports/windows-*.xml'; archiveArtifacts artifacts: 'reports/windows-*,dist/native-preview-windows/**,dist/R-TrustTunnel-Windows-preview.zip,dist/R-TrustTunnel-Windows-x64-Setup.exe*', allowEmptyArchive: true, fingerprint: true } }
        }
      }
    }
    stage('Linux native + full tunnel E2E') {
      when { beforeAgent true; expression { params.RUN_LINUX } }
      agent { label 'macos-arm64' }
      steps {
        unstash 'source'
        sh 'export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"; python3 ci/run.py linux-native-tun python3 ci/linux.py'
      }
      post { always { junit allowEmptyResults: true, testResults: 'reports/linux-*.xml'; archiveArtifacts artifacts: 'reports/linux-*,dist/native-preview-linux/**,dist/service-preview-linux/**', allowEmptyArchive: true, fingerprint: true } }
    }
    stage('macOS + Windows E2E official endpoint') {
      steps {
        script {
          node('macos-arm64') {
            unstash 'source'
            unstash 'macos-bins'
            try {
              sh '''rm -rf .ci-fixture
                JENKINS_NODE_COOKIE=rtrust-fixture python3 ci/endpoint_fixture.py > fixture-run.log 2>&1 &
                echo $! > fixture.pid
                for i in $(seq 1 180); do
                  test -f .ci-fixture/ready && exit 0
                  kill -0 "$(cat fixture.pid)" 2>/dev/null || { cat fixture-run.log; exit 1; }
                  sleep 1
                done
                exit 1
              '''
              sh 'python3 ci/run.py macos-e2e python3 ci/e2e.py .ci-fixture/client.json'
              stash name: 'fixture', includes: '.ci-fixture/client.json', useDefaultExcludes: false
              if (params.RUN_WINDOWS) { node('windows-amd64') {
                unstash 'source'
                unstash 'windows-bins'
                unstash 'fixture'
                try { powershell "python ci/run.py windows-e2e python ci/e2e.py .ci-fixture/client.json; if (\$LASTEXITCODE) { throw 'E2E failed' }" }
                finally {
                  powershell 'Remove-Item .ci-fixture/client.json -ErrorAction SilentlyContinue'
                  junit allowEmptyResults: true, testResults: 'reports/windows-e2e.xml'
                  archiveArtifacts artifacts: 'reports/windows-e2e.*', allowEmptyArchive: true
                }
              }
              }
            } finally {
              sh 'test ! -d .ci-fixture || touch .ci-fixture/stop'
              junit allowEmptyResults: true, testResults: 'reports/macos-e2e.xml'
              archiveArtifacts artifacts: 'reports/macos-e2e.*', allowEmptyArchive: true
            }
          }
        }
      }
    }
    stage('Windows Wintun service E2E') {
      when { expression { params.RUN_WINDOWS && params.WINDOWS_SYSTEM_E2E } }
      steps {
        script {
          node('macos-arm64') {
            unstash 'source'
            try {
              sh '''rm -rf .ci-wintun
                export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
                JENKINS_NODE_COOKIE=rtrust-wintun-fixture python3 ci/windows_fixture.py --protocol "${WINDOWS_TRANSPORT:-trusttunnel}" > wintun-fixture.log 2>&1 &
                echo $! > wintun-fixture.pid
                for i in $(seq 1 180); do
                  test -f .ci-wintun/ready && exit 0
                  kill -0 "$(cat wintun-fixture.pid)" 2>/dev/null || { cat wintun-fixture.log; exit 1; }
                  sleep 1
                done
                exit 1
              '''
              stash name: 'wintun-fixture', includes: '.ci-wintun/client.json', useDefaultExcludes: false
              node('windows-amd64') {
                unstash 'wintun-fixture'
                try { powershell "python ci/run.py windows-service-e2e python ci/windows_service_e2e.py .ci-wintun/client.json; if (\$LASTEXITCODE) { throw 'Wintun E2E failed' }; python ci/run.py windows-full-e2e python ci/windows_full_runner.py .ci-wintun/client.json; if (\$LASTEXITCODE) { throw 'Full tunnel E2E failed' }" }
                finally {
                  powershell 'Remove-Item .ci-wintun -Recurse -Force -ErrorAction SilentlyContinue'
                  junit allowEmptyResults: true, testResults: 'reports/windows-service-e2e.xml,reports/windows-full-e2e.xml'
                  archiveArtifacts artifacts: 'reports/windows-service-e2e.*,reports/windows-full-*', allowEmptyArchive: true
                }
              }
            } finally {
              sh 'test ! -d .ci-wintun || touch .ci-wintun/stop'
            }
          }
        }
      }
    }

  }
}
