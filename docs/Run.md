# Build and Run with Docker

The easiest way to run this tool is to deploy it using Docker.
If you prefer to run it locally, reading the Dockerfile will tell you how.

To deploy it from the latest sources, follow this procedure:
* Clone the repository and change your current directory
* Build the container: `docker build -t <TAG> .`
* Run it like this to see the available commands: `docker run -it <TAG>`. To get help about a specific command, use `docker run -it <TAG> help <COMMAND>`

## Command-Line examples

When running multiple instances is not desired, using BoltDB backend is the best choice as it is lightning fast:

    docker run -it <TAG> --db-type=bolt --db-path=/db/database

Using PostgreSQL enables running multiple instances concurrently. Here is a command line example:

    docker run -it <TAG> --db-type=sql --db-path='host=awesome-database.us-east-1.rds.amazonaws.com port=5432 user=SuperSheep password=SuperSecret' --update-interval=2h --notifier-type=http --notifier-http-url="http://your-notification-endpoint"

The default API port is 6060, read the [API Documentation](API.md) to learn more.

# Build and Run at scale with AWS

CloudFormation templates are available under `cloudformation/` folder. They help deploying the tool in an auto-scaling group behind a load-balancer.
All *.yaml* files are [Jinja2](http://jinja.pocoo.org) templates.

Firstly, you need:
* A publicly accessible PostgreSQL RDS instance
* A HTTP endpoint ready for the notifier if you plan to have notifications
* A signed key pair and the CA certificate if you want to tool to run securely (see [Security.md](Security.md))
* The `cloudformation/` folder and the Python virtual environment: `virtualenv .venv && source .venv/bin/activate && pip install -r requirements.txt`

## Create a new ELB
* Extend or modify the `cloudformation/templates/lb.yaml` to fit your needs
  * The `alarm_actions()` macro which defines actions to be taken by the CloudWatch alarm on the ELB
* Deploy the load balancer with: `python generate_stack.py <YAML_FILE> <AWS_REGION> <AWS_CLOUDFORMATION_BUCKET> <AWS_ACCESS_KEY> <AWS_SECRET_KEY> --upload <STACK_FRIENDLY_NAME>`
* Create a new AWS Route53 A Record alias to the newly create ELB
* Wait until the DNS record is propagated

## Deploy the app
* Extend or modify `cloudformation/templates/app.yaml` to fit your needs
  * Command-line arguments are to be defined in `app_arguments` variable, such as RDS database informations, the notifier endpoint and the keys file paths (which are automatically written in `/etc/certs/quay-sec.crt`, `/etc/certs/quay-sec.key` and `/etc/certs/ca.crt` by the macros below)
  * The `elb_names()` macro to specify the names of the load balancers
  * The `logentries_token` if you want to aggregate the logs on LogEntries
  * The `ssh_key_name` variable and the `ssh_public_keys` macro for the main and secondary SSH public keys
  * The `app_public_key`, `app_private_key`, `app_ca` macros for respectively
* Deploy the stack with: `python generate_stack.py <YAML_FILE> <AWS_REGION> <AWS_CLOUDFORMATION_BUCKET> <AWS_ACCESS_KEY> <AWS_SECRET_KEY> --upload <STACK_FRIENDLY_NAME> --image_tag <TAG>` in which `TAG` is an available tag on the [Quay.io repository](https://quay.io/repository/coreos/quay-sec), such as `latest`
* Wait until the instances appear as healthy in the Load Balancer
* Delete the old stack if there is one
