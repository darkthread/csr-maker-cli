param (
    # CA 提供的 CER 檔 (DER/PEM 格式均可)    
    [Parameter(Mandatory = $true)][string]$CerPath,
    # 私鑰檔 (PEM 格式)
    [Parameter(Mandatory = $true)][string]$PrivKeyPath,
    # IIS 2016 使用舊 PBE 
    [switch]$LegacyIIS
)
$ErrorActionPreference = "Stop"

# 使用 where openssl 尋找 openssl.exe 的路徑
$opensslPath = & cmd /c "where openssl"
if (!($opensslPath -match "openssl.exe")) {
    # 若找不到，嘗試借用 git 的 openssl.exe
    $gitPath = & cmd /c "where git"
    if ($gitPath -match "git.exe") {
        $opensslPath = Resolve-Path(([IO.Path]::GetDirectoryName($gitPath) + "\..\mingw64\bin\openssl.exe")) -ErrorAction SilentlyContinue
        if (!(Test-Path $opensslPath)) {
            $opensslPath = $null
        }
    }
    if (!($opensslPath -match "openssl.exe")) {
        Write-Host "找不到 openssl.exe，請確保已安裝 OpenSSL 並將其加入系統 PATH 環境變數"
        exit 1
    }
}

if (!(Test-Path $CerPath)) {
    Write-Error "找不到憑證檔案: $CerPath"
    exit 1
}
if (!(Test-Path $PrivKeyPath)) {
    Write-Error "找不到私鑰檔案: $PrivKeyPath"
    exit 1
}

$passwd = Read-Host "請輸入金鑰保護密碼" -AsSecureString
$plainPasswd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwd))

$keyIsEncrypted = $PrivKeyPath.EndsWith(".enc")
if ($keyIsEncrypted) {
    $encPrivKeyPath = $PrivKeyPath
    $PrivKeyPath = $encPrivKeyPath -replace "\.enc$", ""
    & $opensslPath enc -d -aes128 -k $plainPasswd -a -iter 100 -pbkdf2 -in $encPrivKeyPath -out $PrivKeyPath
    if ($LASTEXITCODE -ne 0) {
        Remove-Item $PrivKeyPath -ErrorAction SilentlyContinue
        Write-Error "解密私鑰失敗，請檢查密碼是否正確"
        exit 1
    }
}
if (Get-Content $CerPath -Raw | Select-String -Pattern "BEGIN CERTIFICATE") {
    $pemPath = $CerPath
}
else {
    # 若憑證檔不為 PEM 格式，進行 DER / PEM 轉換
    $pemPath = [IO.Path]::ChangeExtension($CerPath, ".pem")
    & $opensslPath x509 -inform DER -in $CerPath -outform PEM -out $pemPath
}
$pfxPath = [IO.Path]::ChangeExtension($CerPath, ".pfx")

if ($LegacyIIS) {
    $pbeParams = "-certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -nomac"
}
else {
    $pbeParams = ""
}
$cmd = "& `"$opensslPath`" pkcs12 -export $pbeParams -out `"$pfxPath`" -inkey `"$PrivKeyPath`" -in `"$pemPath`" -passout pass:$plainPasswd"
Invoke-Expression $cmd
if ($keyIsEncrypted) {
    Remove-Item $PrivKeyPath -ErrorAction SilentlyContinue
}
