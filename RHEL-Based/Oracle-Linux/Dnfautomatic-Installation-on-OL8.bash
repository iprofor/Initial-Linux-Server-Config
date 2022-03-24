# dnf-automatic installation and initial configuration
yum -y install dnf-automatic

# Edit the /etc/dnf/automatic.conf file as per your requirements:
vim /etc/dnf/automatic.conf
# upgrade_type = security
# apply_updates = yes
# emit_via = email
# [email]
# The address to send email messages from.
# email_from = INSERT@EMAIL.HERE
# List of addresses to send messages to.
# email_to = INSERT@EMAIL.HERE

# turn on the service
systemctl enable --now dnf-automatic.timer

# Instead of installing updates we can get notification as follows (make sure you disable dnf-automatic.timer):
systemctl enable --now dnf-automatic-notifyonly.timer

# Just wanted to download updates? Try
systemctl enable --now dnf-automatic-download

