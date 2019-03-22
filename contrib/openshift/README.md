# Openshift Template for Clair

This template is to implement clair inside Openshift.  

## What's inside

Clair : quay.io/coreos/clair:latest  
Postgres: Postgres 9.5 (Persistent Storage)  

## How to Deploy

- Login into Openshift Console.  
- Click 'Import from YAML/JSON'  
- Paste the contents of template.yml file.
- Create > Change the parameters if needed.

If you want to customise the config.yml of clair, you can edit it in configMap inside the template or in Openshift.

To crate the app for the first time, `oc new-app -f template.yml`.

> Wait for few minutes for the application to update and create namespace.
> If you are using klar, you will need to specify the port manually '80'.

## How to update changes

Use the below command to update the existing installation after updating the template. Below command can be used in pipeline as this command will also create app if not exists.

`oc process -f template.yml | oc apply -f -`

## How to destroy

Use the below command to destroy the clair installation completely.

> Below command will also destroy the database volume. You can remove `pvc` from the command, if you want to keep the database files.

`oc delete all,cm,pvc -l app=clair`
