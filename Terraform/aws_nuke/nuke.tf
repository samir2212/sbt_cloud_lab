module "lambda-nuke" {
  source  = "diodonfrost/lambda-nuke/aws"
  version = "2.12.1"
  # insert the 5 required variables here
  cloudwatch_schedule_expression = "cron(0/1 * ? * * *)"
}
