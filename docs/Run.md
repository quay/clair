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
