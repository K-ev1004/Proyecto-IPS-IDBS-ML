$ErrorActionPreference = "Stop"

$dir = "C:\Users\Ciber-UNIPAZ\Desktop\Version 4 Ultra\Proyecto-IPS-IDBS-ML\Captura_Linea_Base"
$dumpcap = "C:\Program Files\Wireshark\dumpcap.exe"
$tshark = "C:\Program Files\Wireshark\tshark.exe"
$capinfos = "C:\Program Files\Wireshark\capinfos.exe"

$interface = "7"  
$durationSec = 300
$volumeCsv = Join-Path $dir "captura_volumen.csv"
$volumeLog  = Join-Path $dir "volumen_log_errores.txt"
$pcapng     = Join-Path $dir "captura_5min.pcapng"

Write-Output "Iniciando captura de $durationSec segundos en interfaz Ethernet (7)..."

$volumeJob = Start-Job -ScriptBlock {
    param($csv, $log, $secs)
    $start = Get-Date
    $written = 0
    $interfaces = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "Ethernet" }
    $adapter = $interfaces | Select-Object -First 1
    if (-not $adapter) {
        "ERROR: adaptador Ethernet no encontrado" | Out-File $log
        return
    }
    $prev = Get-NetAdapterStatistics -Name $adapter.Name
    $prevTime = Get-Date
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("timestamp,rx_bytes_s,tx_bytes_s,rx_pkts_s,tx_pkts_s")
    $prevBytesRx = $prev.ReceivedBytes
    $prevBytesTx = $prev.SentBytes
    $prevPktsRx  = $prev.ReceivedUnicastPackets + $prev.ReceivedMulticastPackets + $prev.ReceivedBroadcastPackets
    $prevPktsTx  = $prev.SentUnicastPackets + $prev.SentMulticastPackets + $prev.SentBroadcastPackets
    while (($(Get-Date) - $start).TotalSeconds -lt $secs) {
        Start-Sleep -Seconds 2
        try {
            $cur = Get-NetAdapterStatistics -Name $adapter.Name
            $curTime = Get-Date
            $dt = ($curTime - $prevTime).TotalSeconds
            if ($dt -le 0) { $dt = 1 }
            $curBytesRx = $cur.ReceivedBytes
            $curBytesTx = $cur.SentBytes
            $curPktsRx  = $cur.ReceivedUnicastPackets + $cur.ReceivedMulticastPackets + $cur.ReceivedBroadcastPackets
            $curPktsTx  = $cur.SentUnicastPackets + $cur.SentMulticastPackets + $cur.SentBroadcastPackets
            $rx = [math]::Max(0, ($curBytesRx - $prevBytesRx) / $dt)
            $tx = [math]::Max(0, ($curBytesTx - $prevBytesTx) / $dt)
            $prx = [math]::Max(0, ($curPktsRx - $prevPktsRx) / $dt)
            $ptx = [math]::Max(0, ($curPktsTx - $prevPktsTx) / $dt)
            $lines.Add(("{0:yyyy-MM-dd HH:mm:ss.fff},{1:N2},{2:N2},{3:N2},{4:N2}" -f $curTime, $rx, $tx, $prx, $ptx))
            $prevBytesRx = $curBytesRx; $prevBytesTx = $curBytesTx
            $prevPktsRx = $curPktsRx; $prevPktsTx = $curPktsTx
            $prevTime = $curTime
            if ($written -lt 600) {
                [System.IO.File]::WriteAllLines($csv, $lines)
                $written++
            }
        } catch {
            "ERR $($_.Exception.Message)" | Out-File $log -Append
        }
    }
}

$pcapJob = Start-Job -ScriptBlock {
    param($dumpcap, $interface, $pcapng, $secs)
    & $dumpcap -i $interface -a duration:$secs -w $pcapng
}

$volumeJob | Wait-Job -Timeout ($durationSec + 30) | Out-Null
$pcapJob | Wait-Job -Timeout ($durationSec + 30) | Out-Null

Receive-Job $volumeJob
Receive-Job $pcapJob

Remove-Item "Microsoft.PowerShell.Core\Function" -ErrorAction SilentlyContinue | Out-Null

Write-Output "=== VOLUMEN ==="
Write-Output "Archivo: $volumeCsv"
Write-Output "=== PAQUETES ==="
Write-Output "Archivo: $pcapng"
