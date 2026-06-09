# Bastion-host SSH access keys for the operations team.
resource "aws_key_pair" "ops_rsa" {
  key_name = "ops-bastion"
  # Legacy RSA key — quantum-vulnerable, scheduled for rotation.
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDxampleNotARealKey ops@corp"
}

resource "aws_key_pair" "ops_ecdsa" {
  key_name = "ops-bastion-ec"
  # ECDSA P-256 host key — also broken by Shor's algorithm.
  public_key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYxampleKey ops@corp"
}
