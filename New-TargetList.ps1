function New-TargetList {
<#
.SYNOPSIS
Dynamically builds a list of targetable hosts.

.DESCRIPTION
This cmdlet can test Windows Remote Management and configure it if it's not already configured.

Specify computers by name or IP address.

Use the -Verbose switch to see detailed information.

.PARAMETER NetworkAddress 
Specify an IPv4 network, requires either the NetMask or CidrMask parameter.

.PARAMETER NetMask 
Specify the network mask as an IPv4 address, for use with NetworkAddress parameter.

.PARAMETER CidrMask
Specify the network mask in CIDR notation, for use with NetworkAddress parameter.

.PARAMETER StartAddress
Specify an IPv4 address at the beginning of a range of addresses.

.PARAMETER EndAddress
Specify an IPv4 address at the end of a range of addresses.

.PARAMETER CidrNetwork
Specify a single IPv4 network or a list of networks in CIDR notation.

.PARAMETER NoStrikeList
Specify the path to a list of IPv4 addresses that should never be touched.

.PARAMETER ResolveIp
Attemtps to Resolve IPv4 addresses to hostnames using DNS lookups.

.PARAMETER Randomize
Randomizes the list of targets returned.

.EXAMPLE
The following example builds a list of IP addresses from 10.10.10.1-10.10.10.254 and 10.10.20.1-10.10.20.254

PS C:\> New-TargetList -CidrNetwork 10.10.10.0/24,10.10.20.0/24

.NOTES
Version: 0.1
Author : Jesse Davis (@secabstraction)
#>
    Param(
        [Parameter(ParameterSetName = "NetMask", Position = 0, Mandatory = $true)]
        [Parameter(ParameterSetName = "CidrMask", Position = 0, Mandatory = $true)]
	    [String]$NetworkAddress,
        
        [Parameter(ParameterSetName = "NetMask", Position = 1, Mandatory = $true)]
	    [String]$NetMask,
    
        [Parameter(ParameterSetName = "CidrMask", Position = 1, Mandatory = $true)]
	    [String]$CidrMask,

        [Parameter(ParameterSetName = "IpRange", Position = 0, Mandatory = $true)]
	    [String]$StartAddress,

        [Parameter(ParameterSetName = "IpRange", Position = 1, Mandatory = $true)]
	    [String]$EndAddress,

        [Parameter(ParameterSetName = "FullCidr", Position = 0, Mandatory = $true)]
	    [String[]]$CidrNetwork,

        [Parameter()]
	    [String]$NoStrikeList,

        [Parameter()]
	    [Switch]$FindAlives,

        [Parameter()]
	    [Switch]$ResolveIp,

        [Parameter()]
	    [Switch]$Randomize
    ) #End Param

    #region HELPERS
    function local:Convert-Ipv4ToInt64 {  
        param (
            [Parameter()]
            [String]$Ipv4Address
        )  
            $Octets = $Ipv4Address.split('.')  
            Write-Output ([Int64](  [Int64]$Octets[0] * 16777216 + [Int64]$Octets[1] * 65536 + [Int64]$Octets[2] * 256 + [Int64]$Octets[3]  ))  
    }    
    function local:Convert-Int64ToIpv4 {  
        param (
            [Parameter()]
            [Int64]$Int64
        )   
            Write-Output (([Math]::Truncate($Int64 / 16777216)).ToString() + "." + ([Math]::Truncate(($Int64 % 16777216) / 65536)).ToString() + "." + ([Math]::Truncate(($Int64 % 65536) / 256)).ToString() + "." + ([Math]::Truncate($Int64 % 256)).ToString()) 
    } 
    #endregion HELPERS

    #regex for input validation
    $IPv4 = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    $IPv4_CIDR = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$"   
                
    $IpList = New-Object Collections.Arraylist

    #Build IP Address list
    if ($PSCmdlet.ParameterSetName -eq "FullCidr") {
        Write-Verbose "Building target list..."
        
        foreach ($Cidr in $CidrNetwork) {
            if ($Cidr -notmatch $IPv4_CIDR) {
                Write-Warning "$Cidr is not a valid CIDR network!"
                continue
            }

            $Split = $Cidr.Split('/')
            $Net = [Net.IPAddress]::Parse($Split[0])
            $Mask = [Net.IPAddress]::Parse((Convert-Int64ToIpv4 -Int64 ([Convert]::ToInt64(("1" * $Split[1] + "0" * (32 - $Split[1])), 2))))
            
            $Network = New-Object Net.IPAddress ($Mask.Address -band $Net.Address)
            $Broadcast = New-Object Net.IPAddress (([Net.IPAddress]::Parse("255.255.255.255").Address -bxor $Mask.Address -bor $Network.Address))

            $Start = Convert-Ipv4ToInt64 -Ipv4Address $Network.IPAddressToString
            $End = Convert-Ipv4ToInt64 -Ipv4Address $Broadcast.IPAddressToString

            for ($i = $Start + 1; $i -lt $End; $i++) { [void]$IpList.Add((Convert-Int64ToIpv4 -Int64 $i)) }
        } 
    }
    if ($PSCmdlet.ParameterSetName -eq "CidrMask") {       
        Write-Verbose "Building target list..."

        if ($NetworkAddress -notmatch $IPv4) { 
            Write-Warning "$NetworkAddress is not a valid IPv4 address!"
            break
        }
        
        $Net = [Net.IPAddress]::Parse($NetworkAddress)
        $Mask = [Net.IPAddress]::Parse((Convert-Int64ToIpv4 -Int64 ([Convert]::ToInt64(("1" * $CidrMask + "0" * (32 - $CidrMask)), 2))))
            
        $Network = New-Object Net.IPAddress ($Mask.Address -band $Net.Address)
        $Broadcast = New-Object Net.IPAddress (([Net.IPAddress]::Parse("255.255.255.255").Address -bxor $Mask.Address -bor $Network.Address))

        $Start = Convert-Ipv4ToInt64 -Ipv4Address $Network.IPAddressToString
        $End = Convert-Ipv4ToInt64 -Ipv4Address $Broadcast.IPAddressToString

        for ($i = $Start + 1; $i -lt $End; $i++) { [void]$IpList.Add((Convert-Int64ToIpv4 -Int64 $i)) }
    }
    if ($PSCmdlet.ParameterSetName -eq "NetMask") {       
        Write-Verbose "Building target list..."

        if ($NetworkAddress -notmatch $IPv4) { 
            Write-Warning "$NetworkAddress is not a valid IPv4 address!"
            break
        }
        if ($NetMask -notmatch $IPv4) { 
            Write-Warning "$NetMask is not a valid network mask!"
            break
        }

        $Net = [Net.IPAddress]::Parse($NetworkAddress)
        $Mask = [Net.IPAddress]::Parse($NetMask)

        $Network = New-Object Net.IPAddress ($Mask.Address -band $Net.Address)
        $Broadcast = New-Object Net.IPAddress (([Net.IPAddress]::Parse("255.255.255.255").Address -bxor $Mask.Address -bor $Network.Address))

        $Start = Convert-Ipv4ToInt64 -Ipv4Address $Network.IPAddressToString
        $End = Convert-Ipv4ToInt64 -Ipv4Address $Broadcast.IPAddressToString

        for ($i = $Start + 1; $i -lt $End; $i++) { [void]$IpList.Add((Convert-Int64ToIpv4 -Int64 $i)) }
    }
    if ($PSCmdlet.ParameterSetName -eq "IpRange") {
        Write-Verbose "Building target list..."

        if ($StartAddress -notmatch $IPv4) { 
            Write-Warning "$StartAddress is not a valid IPv4 address!"
            break
        }
        if ($EndAddress -notmatch $IPv4) { 
            Write-Warning "$EndAddress is not a valid network mask!"
            break
        }

        $Start = Convert-Ipv4ToInt64 -Ipv4Address $StartAddress
        $End = Convert-Ipv4ToInt64 -Ipv4Address $EndAddress

        for ($i = $Start ; $i -le $End; $i++) { [void]$IpList.Add((Convert-Int64ToIpv4 -Int64 $i)) }
    }

    ######### Remove Assets #########
    if ($PSBoundParameters['NoStrikeList']) {
        
        $ExclusionList = New-Object Collections.Arraylist

        $NoStrike = Get-Content $NoStrikeList | Where-Object {$_ -notmatch "^#"} #skip lines commented out
        foreach ($Ip in $NoStrike) {
            if ( $Ip -match $IPv4 ) { $ExclusionList.Add($Ip) }
            else { 
                try { $ResolvedIp = ([Net.DNS]::GetHostByName("$Ip")).AddressList[0].IPAddressToString } #if list contains hostnames, try to resolve IP address
                catch { 
                    Write-Warning "$Ip does not resolve to a valid IPv4 address!" 
                    continue
                }
                $ExclusionList.Add($ResolvedIp)
            }
        }
        $ValidTargets = $IpList | Where-Object { $ExclusionList -notcontains $_ }
    }
    else { $ValidTargets = $IpList }

    ######### Randomize list #########
    if ($Randomize.IsPresent) {
        Write-Verbose "Randomizing target list..."
        $Random = New-Object Random
        $ValidTargets = ($ValidTargets.Count)..1 | ForEach-Object { $Random.Next(0, $ValidTargets.Count) | ForEach-Object { $ValidTargets[$_]; $ValidTargets.RemoveAt($_) } }
    }

    ########## Find Alives & Resolve Hostnames ###########
    if ($FindAlives.IsPresent -and $ResolveIp.IsPresent) {
        Write-Verbose "Finding alive hosts..."

        $AliveTargets = Invoke-Expression "$Torch\HostSOP\fping.exe $ValidTargets -n 1 -p -t 10 " | grep "Reply" | gawk '{print $3}' | sed 's/://g'
        Write-Verbose "    $($AliveTargets.Count) hosts alive..."

        if ($AliveTargets.Count -lt 1) {
            Write-Warning "No alive hosts found. If hosts are responding to ping, check configuration."
            break
        }
        else {
            Write-Verbose "Resolving hostnames, this may take a while..."

            $ResolvedHosts = New-Object Collections.Arraylist
            $i = 1
            foreach ($Ip in $AliveTargets) {
                #Progress Bar
                Write-Progress -Activity "Resolving Hosts - *This may take a while*" -Status "Hosts Processed: $i of $($AliveTargets.Count)" -PercentComplete ($i / $AliveTargets.Count * 100)
        
                #Resolve the name of the host
                $CurrentEAP = $ErrorActionPreference
                $ErrorActionPreference = "SilentlyContinue"
                [void]$ResolvedHosts.Add(([Net.DNS]::GetHostByAddress($Ip)).HostName)
                $ErrorActionPreference = $CurrentEAP
                
                $i++
            }
            Write-Progress -Activity "Resolving Hosts" -Status "Done" -Completed
            Write-Output $ResolvedHosts
        }
    }
    
    ########## Only Find Alives ##############
    elseif ($FindAlives.IsPresent -and !$ResolveIp.IsPresent) {
        Write-Verbose "Finding alive hosts..."

        $AliveTargets = Invoke-Expression "$Torch\HostSOP\fping.exe $ValidTargets -n 1 -p -t 10 " | grep "Reply" | gawk '{print $3}' | sed 's/://g'
        Write-Verbose "    $($AliveTargets.Count) hosts alive..."

        if ($AliveTargets.Count -lt 1) {
            Write-Warning "No alive hosts found. If hosts are responding to ping, check configuration."
            break
        }  
        else { 
            Write-Verbose "    $($AliveTargets.Count) alive and targetable hosts..."
            Write-Output $AliveTargets 
        }
    }

    ########## Only Resolve Hostnames ########
    elseif ($ResolveIp.IsPresent -and !$FindAlives.IsPresent) {
        Write-Verbose "Resolving hostnames, this may take a while..."

        $ResolvedHosts = New-Object Collections.Arraylist
        $i = 1
        foreach ($Ip in $ValidTargets) {
            #Progress Bar
            Write-Progress -Activity "Resolving Hosts - *This may take a while*" -Status "Hosts Processed: $i of $($ValidTargets.Count)" -PercentComplete ($i / $ValidTargets.Count * 100)
        
            #Resolve the name of the host
            $CurrentEAP = $ErrorActionPreference
            $ErrorActionPreference = "SilentlyContinue"
            [void]$ResolvedHosts.Add(([Net.DNS]::GetHostByAddress($Ip)).HostName)
            $ErrorActionPreference = $CurrentEAP
                
            $i++
        }
        Write-Progress -Activity "Resolving Hosts" -Status "Done" -Completed
        Write-Output $ResolvedHosts
    }
    
    ########## Don't find alives or resolve ########
    else { Write-Output $ValidTargets }
}
