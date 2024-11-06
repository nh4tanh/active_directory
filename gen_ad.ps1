param([Parameter(Mandatory=$true)] $JSONFile)

function CreateADGroup {
    param([Parameter(Mandatory=$true)] $groupObject)

    $name = $groupObject.name
    New-ADGroup -name $name -GroupScope Global
    
}

function CreateADUser {
    param([Parameter(Mandatory=$true)] $userObject)

    $name = $userObject.name
    $password = $userObject.password

    # Generate username from name
    $firstname, $lastname = $name.Split(" ")
    $username = ($name[0] + $name.Split(" ")[1]).ToLower()
    $SamAccountName = $username
    $principalname = $username

    # Actually create the AD user object
    New-ADUser -Name "$name" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount 

    # Add user to its group
    foreach($group_name in $userObject.groups){
        try {
            Get-ADGroup -Identity $group_name
            ADD-ADGroupMember -Identity $group_name -Members $username
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
        {
            Write-Warning “User $name NOT added to group $group_name because it does not exist”
        }
    }

    #Add to local admin as needed
    # if( $userObject.local_admin){
    #     net localgroup administrators $Global:Domain\$username /add
    # } 
    $add_command = "net localgroup administrators $Global:Domain\$username /add"
    foreach($hostname in $userObject.local_admin){
        echo "Invoke-Command -Computer $hostname -ScriptBlock { $add_command }" | Invoke-Expression
    }
}

function RemoveADUser {
    param([Parameter(Mandatory=$true)] $userObject)

    $name = $userObject.name
    $firstname, $lastname = $name.Split(" ")
    $username = ($name[0] + $name.Split(" ")[1]).ToLower()
    $SamAccountName = $username

    Remove-ADUser -Identity $SamAccountName -confirm:$false
}

function WeakenPasswordPolicy(){
    secedit /export /cfg C:\Windows\Tasks\secpol.cfg
    (Get-Content C:\Windows\Tasks\secpol.cfg).replace("PasswordComplexity = 1", "PasswordComplexity = 0").replace("MinimumPasswordLength = 7", "MinimumPasswordLength = 1") | Out-File C:\Windows\Tasks\secpol.cfg
    secedit /configure /db C:\windows\security\local.sdb /cfg C:\Windows\Tasks\secpol.cfg /areas SECURITYPOLICY
    rm -force C:\Windows\Tasks\secpol.cfg -confirm:$false 
}

WeakenPasswordPolicy

$json = (Get-Content $JSONFile | ConvertFrom-Json)

$Global:Domain = $json.domain

foreach($group in $json.groups){
    CreateADGroup $group
}

foreach($user in $json.users){
    CreateADUser $user
}
