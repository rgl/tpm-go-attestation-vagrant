param(
    $serverIpAddress='10.11.0.101',
    $clientIpAddress='10.11.0.202'
)

# install service dependencies.
choco install -y nssm carbon openssl.light
Import-Module Carbon

# install go.
choco install -y golang --version 1.18.2

# update $env:PATH with the recently installed Chocolatey packages.
Import-Module "$env:ChocolateyInstall\helpers\chocolateyInstaller.psm1"
Update-SessionEnvironment

# build.
$env:CGO_ENABLED = '0'
go build -ldflags="-s" -o="$env:TEMP\client.exe"
go install -v github.com/google/go-attestation/attest/attest-tool@v0.4.3

# install as service.
# NB this must run with Administrative privileges; so running as SYSTEM will do.
$serviceName = 'tpm-go-attestation-client'
$serviceUsername = 'SYSTEM'
$serviceHome = "C:\$serviceName"
mkdir $serviceHome -Force | Out-Null
Copy-Item "$env:TEMP\client.exe" $serviceHome
Disable-CAclInheritance $serviceHome
Grant-CPermission $serviceHome $serviceUsername FullControl
Grant-CPermission $serviceHome $env:USERNAME FullControl
Grant-CPermission $serviceHome Administrators FullControl
Write-Host "Creating the $serviceName service..."
nssm install $serviceName "$serviceHome\client.exe"
nssm set $serviceName AppDirectory $serviceHome
nssm set $serviceName AppEnvironmentExtra `
    APP_NAME="$($env:COMPUTERNAME.ToLowerInvariant())" `
    SERVER_BASE_ADDRESS="http://${serverIpAddress}:8000" `
    CLIENT_BASE_ADDRESS="http://${clientIpAddress}:9000"
nssm set $serviceName Start SERVICE_DEMAND_START
nssm set $serviceName AppRotateFiles 1
nssm set $serviceName AppRotateOnline 1
nssm set $serviceName AppRotateSeconds 86400
nssm set $serviceName AppRotateBytes 1048576
nssm set $serviceName AppStdout $serviceHome\$serviceName-stdout.log
nssm set $serviceName AppStderr $serviceHome\$serviceName-stderr.log
Start-Service $serviceName

# add firewall rule to allow inbound access to port 9000.
Write-Host "Creating the firewall rule to allow inbound TCP/IP access to the $serviceName port 9000..."
New-NetFirewallRule `
    -Name "$serviceName-In-TCP" `
    -DisplayName "$serviceName (TCP-In)" `
    -Direction Inbound `
    -Enabled True `
    -Protocol TCP `
    -LocalPort 9000 `
    | Out-Null

# show information about the tpm.
Write-Host 'Getting the TPM information...'
attest-tool info

# do a self-test attestation.
Write-Host 'Doing a TPM self-test...'
attest-tool self-test
