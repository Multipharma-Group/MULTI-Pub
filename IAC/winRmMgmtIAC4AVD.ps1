# Here’s a ready-to-use ARM template snippet to run a PowerShell script on a Windows VM at FIRST boot using the Custom Script Extension.
# That’s usually the cleanest for production VMs:

{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Compute/virtualMachines/extensions",
      "name": "[concat(parameters('vmName'), '/CustomScriptExtension')]",
      "apiVersion": "2021-07-01",
      "location": "[parameters('location')]",
      "properties": {
        "publisher": "Microsoft.Compute",
        "type": "CustomScriptExtension",
        "typeHandlerVersion": "1.10",
        "autoUpgradeMinorVersion": true,
        "settings": {
          "fileUris": [
            #"https://<storage-account>.blob.core.windows.net/scripts/init.ps1"
			"https://raw.githubusercontent.com/<org>/<repo>/<branch>/scripts/init.ps1"
          ],
          "commandToExecute": "powershell -ExecutionPolicy Unrestricted -File init.ps1"
        }
      },
      "dependsOn": [
        "[resourceId('Microsoft.Compute/virtualMachines', parameters('vmName'))]"
      ]
    }
  ],
  "parameters": {
    "vmName": {
      "type": "string"
    },
    "location": {
      "type": "string",
      "defaultValue": "[resourceGroup().location]"
    }
  }
}

