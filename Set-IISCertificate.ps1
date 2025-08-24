param (
    [Parameter(Mandatory = $true)][string]$WebSiteName,
    [string]$PfxPath,
    [string]$Password
)

# 【工具語法範例】
# 列舉 IIS 站台資料
# Set-IISCertficate.ps1 ? 
# 顯示 IIS 站台憑證設定
# Set-IISCertificate.ps1 "Default Web Site"
# 安裝 PFX 憑證並設定 IIS 站台使用 (互動式輸入私鑰密碼)
# Set-IISCertificate.ps1 "Default Web Site" "X:\path\cert.pfx" 
# 安裝 PFX 憑證並設定 IIS 站台使用 (直接提供私鑰密碼)
# Set-IISCertificate.ps1 "Default Web Site" "X:\path\cert.pfx" "priv-key-password"

$ErrorActionPreference = "Stop"
function DisplayProperty($propName, $value) {
    Write-Host " - $($propName): " -ForegroundColor Yellow -NoNewline
    Write-Host $value
}

function DisplayCertificate($title, $cert) {
    Write-Host "[$title]" -ForegroundColor Cyan
    DisplayProperty "憑證主體" $cert.Subject
    DisplayProperty "發 行 者" $cert.Issuer
    DisplayProperty "有效日期" "$($cert.NotBefore) - $($cert.NotAfter)"
    DisplayProperty "憑證指紋" $cert.Thumbprint
}
# 自動改用管理者身分執行：https://blog.darkthread.net/blog/ps1-requireadministrator/
$wp = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-Not $wp.IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    $rawCmd = $MyInvocation.Line
    $rawArgs = $rawCmd.Substring($rawCmd.IndexOf('.ps1') + 4)
    # When run with file explorer context menu,
    #if ((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'D:\Restart-WinService.ps1'
    if ($rawCmd.StartsWith('if')) { $rawArgs = '' }
    Start-Process Powershell -Verb RunAs -ArgumentList "-NoExit", "$PSCommandPath $rawArgs"
}
else {
    Import-Module WebAdministration
    if ($WebSiteName -eq '?') {
        # 列舉所有網站並顯示其繫結(http or https)
        Get-Website | Select-Object Name, PhysicalPath, @{Name='Bindings';Expression={($_.Bindings.Collection | Where-Object { $_.protocol -eq 'http' -or $_.protocol -eq 'https' } | ForEach-Object { "$($_.protocol)://$($_.bindingInformation)" }) -join ' '}} | ForEach-Object {
            Write-Host "網站[$($_.Name)]" -ForegroundColor Cyan
            DisplayProperty "路徑" $_.PhysicalPath
            DisplayProperty "繫結" $_.Bindings
        }
        return
    }
    else {
        $certs = Get-ChildItem "cert:\LocalMachine\My"
        # Check if website has HTTPS binding
        $binding = Get-WebBinding -Name $WebSiteName -Protocol "https"
        if ($binding) {
            $cert = $certs | Where-Object { $_.Thumbprint -eq $binding.CertificateHash }
            if ($cert) {
                DisplayCertificate '網站現有憑證' $cert
            }
            else {
                Write-Host "網站未設定憑證: $WebSiteName" -ForegroundColor Magenta
            }
        }
        else {
            Write-Host "網站未設定 HTTPS: $WebSiteName" -ForegroundColor Red
            return
        }
        if ($PfxPath) {

            if (-Not (Test-Path $PfxPath)) {
                Write-Host "憑證檔案不存在: $PfxPath" -ForegroundColor Red
                return
            }

            # 轉絕對路徑以適用 .NET 程式庫
            $PfxPath = Resolve-Path $PfxPath

            if ($Password) {
                $plainPasswd = $Password
                $privKeyPassword = ConvertTo-SecureString -String $plainPasswd -AsPlainText -Force
            }
            else {
                $privKeyPassword = Read-Host "請輸入私鑰密碼" -AsSecureString
                $plainPasswd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($privKeyPassword))
            }

            # 檢查憑證是否已存在
            # PS 7 可使用 Get-PfxCertificate -FilePath $PfxPath -Password $Password 
            # PS 5.1 不提供 -Password 參數，改用 X509Certificate2
            $newCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            Write-Host "嘗試匯入憑證: $PfxPath" -ForegroundColor Green
            $newCert.Import($PfxPath, $plainPasswd, 'DefaultKeySet')
            $existingCert = $certs | Where-Object { $_.Thumbprint -eq $newCert.Thumbprint }
            if ($existingCert) {
                Write-Host "憑證已存在，不需匯入" -ForegroundColor Yellow
            }
            else {
                Write-Host "匯入憑證: $PfxPath" -ForegroundColor Green
                Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $privKeyPassword -ErrorAction Stop | Out-Null
            }

            DisplayCertificate '新憑證' $newCert

            $confirm = Read-Host "是否確定要更新網站憑證? (Y/N)"
            if ($confirm -ne 'Y') {
                Write-Host "操作已取消" -ForegroundColor Magenta
                return
            }

            # Add or update the certificate in IIS binding
            if ($binding) {
                Write-Host "更新網站憑證: $WebSiteName" -ForegroundColor Green
                $binding.AddSslCertificate($newCert.Thumbprint, "My")
            }
        }
    }
}