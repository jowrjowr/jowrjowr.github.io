layout: page
title: "IAM RDS Authentication in Ecto"
date: 2020-11-09 12:00:00 -0000
categories: elixir ecto iam rds

# Introduction 

A big problem with managing database access is managing credentials. Every facet is a nuisance. Storing, retreiving, retiring. All securely. 

It turns out that AWS offers a cool feature called [IAM RDS authentication](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.Connecting.html) which lets an *AWS* authenticated user authenticate to an appropriately configured database without having stored credentials. 

The overall idea here is to show how to implment this in Elixir using Ecto, as when I figured this out there was litearlly no documentation on the subject and there's been some requests for this info.

# Pre-requisites

Note: Please refer to the [AWS documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.Connecting.html) and its subsequent links for how this works in general. I am assuming basic familiarity so I don't have to replicate everything AWS says.

For the infrastructure side of things I use [Terraform](https://www.terraform.io/) with the AWS and postgres providers to manage the database infrastructure.

# Database setup

There is two parts to the database side.

1. The database instance must be configured to allow this. 

Managing with something like this is straight forward in terraform. I have made public a terraform module for managing database configuration [viewable here](https://github.com/jowrjowr/terraform-aws-database), but the salient part in the `aws_db_instance` resource is the `iam_database_authentication_enabled` attribute. All you have to do is set it to be true, and reboot at an appropriate time. 

One could do all of this by hand without Terraform but let's say that is not a suggested configuration.

Note: This change does not negatively impact anything by having it enabled. Many specific, explicit configuration steps must be taken to utilize this.


2. The database user must be configured to use the flow.

The user for this authentication method must be chosen and be distinct from normal user authentication as IAM breaks the normal flow. Otherwise all it needs is the `iam_rds` role attached.

In terraform:

```
resource "postgresql_role" "application_iam" {
  name       = "application_iam"
  login      = true
  roles      = ["rds_iam"]
}
```

On a related note, with how tightly coupled infrastructure and application code become, this is why I prefer storing infrastructure code with application code. 

# IAM/EC2 Setup

A valid question/concern would be "Doesn't this mean any AWS user or EC2 instance can access the database? 

Thankfully the answer is no. But that does mean we need to put in a bit of work. The next part is making sure the EC2 instance can authenticate. We'll be leveraging [EC2 instance policies](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html) to make this work. 

The EC2 instance, either direct or managed via an autoscaling group, requires an instance profile in order to give the instance permission to authenticate. This is attached easily with the `aws_launch_template` resource's `iam_instance_profile` attribute.

I won't belabor too deeply on how this works as this is pretty standard stuff in the AWS/Terraform side of the house. Check out the [AWS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.IAMPolicy.html) or [Terraform](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_template) as necessary.


```data "aws_iam_policy_document" "application" {
  statement {
    actions = [
      "rds-db:connect"
    ]
    resources = [
      "arn:aws:rds-db:${var.region}:${var.account_id}:dbuser:*/application_iam"
    ]
    effect = "Allow"
  }
}
```

I used a glob in place of the DB identifier because with environments that have multiple databases make this a nuisance to deal with. Tuning for flavor is encouraged.

# Testing

I explicitly lay this out because you need to test whether the instance can successfully authenticate to the database before Elixir work can be meaningfully debugged. The [documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.Connecting.AWSCLI.PostgreSQL.html) lays out how to do this.

Thankfully once it works, it is brick stable unless IAM is changed.

# Ecto

The theory for this is conceptually pretty simple.

A normal Ecto repo's init/2 for a static credential set is going to look something like this. 

```
  def init(_arg, config) do
    # there is a headscratcher of an ecto issue in play that justifies putting
    # credentials in both the init and configure call
    # init only: works
    # configure only: works and then gets stuck midway
    # both: works

    # NOTE: SSL is required in AWS, and won't exist otherwise.

    config =
      config
      |> Keyword.put(:database, Application.AppConfig.get(:pg_database))
      |> Keyword.put(:hostname, Application.AppConfig.get(:pg_hostname))
      |> Keyword.put(:username, Application.AppConfig.get(:pg_username))
      |> Keyword.put(:password, Application.AppConfig.get(:pg_username))
    {:ok, config}
  end
```

The first pass implementation was the reasonable one: What if we make the password keyword dynamic? That works, but only once. You are even lured into thinking you are done by it working for multiple hours until postgrex decides it needs to make a new connection. 

Instead, we need to go deeper and understand how Ecto works. Ecto hands off connection handling to the Postgrex adapter. Postgrex documentation and code offers us no _specific_ solutions, but does have [this](https://github.com/elixir-ecto/postgrex/blob/1960fbc305155200fa9ff69c6dd49377e9cf1c62/lib/postgrex.ex#L121) to say:

```
  `Postgrex` uses the `DBConnection` library and supports all `DBConnection`
  options like `:idle`, `:after_connect` etc. See `DBConnection.start_link/2`
  for more information.
```

So let's examine DBConnection.start_link/2. The [documentation](https://hexdocs.pm/db_connection/DBConnection.html#start_link/2) offers the following option:

```
:configure - A function to run before every connect attempt to dynamically configure the options, either a 1-arity fun, {module, function, args} with options prepended to args or nil where only returned options are passed to connect callback (default: nil)
```

This is the magic that we need that allows us to dynamically reconfigure options every connection attempt, instead of once at startup. I am being literal with "every". This applies to _any_ connection, including normal drops and timeouts. This was a serious concern and was not obviously the case.

So, we have to rewrite how the entire repo setup works. Let's go through it step by step. This is framed in the context of how an existing project was written and YMMV in terms of structure.

1. mix.exs

We need some new toys so we aren't interacting with the AWS metadata service by hand, which is unfair to everyone. Adjust versioning to taste, I expect increments since the reference project was last updated.

```
    {:dns, "~> 2.1.2"},
    {:ex_aws, "~> 2.1"},
    {:ex_aws_rds, "~> 2.0"},
    {:ex_aws_ec2, "~> 2.0"}
```

1. config.ex (or where-ever you have Mix.Config stuff stored)

We need to alter the configuration to make sure each repo runs the callback. 

```
config :order_manager, Application.Repo,
  show_sensitive_data_on_connection_error: true,
  queue_target: 100,
  pool_size: 20,
  configure: {Application.Repo, :configure, []}
```

Additionally the ex_aws module needs to be configured. We aren't using stored keys, so this is straight forward:

```
config :ex_aws,
  region: "<region>, eg eu-west-1"
```

The metadata service has been recently updated to _finally_ show what region you are in so this can be dynamically determined if this is an issue. `ex_aws_ec2` doesn't have support for that right now but that is a relatively minor thing I believe.

2. repo.ex

The repo is going to look a little bit different now. In our environment, there were two basic sub-environments: AWS, and "not AWS". This requires a little bit of flexibility that I'll show how to address.

Note: The mix environment being `prod` means only that the project was built to deploy, not that it is running in production. We had `dev` and `staging` environments along with `prod` and they all run the `prod` Mix environment. This has confused everyone at least once. 

```
defmodule Application.Repo do
  use Ecto.Repo,
    otp_app: :application,
    adapter: Ecto.Adapters.Postgres

  import ThirdpartyAPI.AWS.IAM_RDS

  @prod Mix.env() == :prod

  def init(_arg, config) do

    # NOTE: SSL is required in AWS, and won't exist otherwise.

    config =
      config
      |> Keyword.put(:database, Application.AppConfig.get(:pg_database))
      |> Keyword.put(:hostname, Application.AppConfig.get(:pg_hostname))
      |> Keyword.put(:username, Application.AppConfig.get(:pg_username))
      |> Keyword.put(
        :password,
        generate_rds_password(
          :pg_hostname,
          :pg_username,
          :pg_password
        )
      )
      |> Keyword.put(:ssl, @prod)

    {:ok, config}
  end

  def configure(config) do
    # this gets re-ran every time a new connection is made, as opposed to
    # init/2 which gets ran at startup. this allows for dynamic password
    # generation - necessary for IAM RDS authentication.

    config
    |> Keyword.put(
      :password,
      generate_rds_password(
        :pg_hostname,
        :pg_username,
        :pg_password
      )
    )
  end
end
```

3. iam_rds.ex

This contains the password generation algorithm as built. 

A lot of this can be simplified in a different environment. This allowed maximum flexibility between local/CI environments that do not use RDS and formally deployed environments that do. Including accounting for DNS CNAME issues. 

With the CNAME, an integral part of the password is the host of the database instance _as AWS understands it_ rather than how we might understand it for our own purposes. DNS here is a potential painpoint that might be written a little bit better, but the standard Elixir faliure mode into a stacktrace should be fine. Adjust to taste.

Please review the documentation linked earlier, as well as how `ex_aws_rds` [here](https://hexdocs.pm/ex_aws_rds/ExAws.RDS.html#generate_db_auth_token/4).

```
defmodule ThirdpartyAPI.AWS.IAM_RDS do
  @prod Mix.env() == :prod

  # documentation on how this works:
  # https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.Connecting.html

  def generate_rds_password(hostname, username, password) do
    # we have two fundamental cases: AWS and "not AWS"
    # AWS will only ever be in Mix.env() == :prod, in which
    # credentials are dynamically generated via instance roles.
    # otherwise they are hardcoded.

    if @prod do
      # we need to first take the DNS CNAME and get the RDS hostname
      # this is still preferrable to storing hardcoded data.

      {:ok, [hostname | _]} =
        Application.AppConfig.get(hostname)
        |> DNS.resolve()

      password =
        ExAws.RDS.generate_db_auth_token(
          hostname,
          Application.AppConfig.get(username),
          5432
        )

      password
    else
      # catchall. handles :dev and :test specifically.
      # the non-AWS stuff, in other words.

      Application.AppConfig.get(password)
    end
  end
end
```

This should be enough to get IAM RDS auth working with Elixir. You can do the same thing with MySQL if you need to, as well.
