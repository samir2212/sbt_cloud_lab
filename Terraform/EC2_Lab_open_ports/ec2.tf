data "aws_vpc" "default" {
}

data "aws_subnet_ids" "public" {
  vpc_id = data.aws_vpc.default.id
}

data "aws_ami" "amazon-linux-2" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm*"]
  }
}

module "ec2-instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 3.0"

  name = var.project
  #for_each               = data.aws_subnet_ids.public.ids
  ami                    = data.aws_ami.amazon-linux-2.id
  instance_type          = var.ec2_type
  subnet_id              = element(tolist(data.aws_subnet_ids.public.ids), 0)
  monitoring             = true
  vpc_security_group_ids = ["${aws_security_group.ec2-sg.id}"]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.id

  tags = {
    Name = "${var.project}"
  }
}

resource "aws_security_group" "ec2-sg" {
  name        = "${var.project}-ec2-sg"
  description = "allow inbound access from the internet"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "ec2_role" {
  name = "ec2_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }
}
EOF
  tags = {
    CloudLabRole = "SBT"
  }
}

resource "aws_iam_role_policy_attachment" "ssm_core_attach-to-ec2_role" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ssm_attach-to-ec2_role_2" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile"
  role = aws_iam_role.ec2_role.name
}
