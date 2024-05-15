#!/usr/bin/env python3
# Data Visualization
# Author Yehia Elghaly

import matplotlib.pyplot as plt

def create_email_domain_chart(emails):
    domains = {}
    for email in emails:
        domain = email.split('@')[1]
        domains[domain] = domains.get(domain, 0) + 1

    # Create a bar chart
    plt.bar(domains.keys(), domains.values())
    plt.xlabel('Email Domains')
    plt.ylabel('Count')
    plt.title('Email Domain Distribution')
    plt.show()

def create_ip_address_chart(ip_addresses):
    # Create a pie chart
    plt.pie(ip_addresses.values(), labels=ip_addresses.keys(), autopct='%1.1f%%')
    plt.title('IP Address Distribution')
    plt.axis('equal')
    plt.show()

def main():
    emails = [
        'yehia.elghaly@gmail.com',
        'yehia.elghaly@cc.com',
        'admin@admin.com',
        'root@root.net'
    ]

    ip_addresses = {
        '192.168.1.1': 1,
        '172.176.1.121': 1,
        '192.168.4.4': 1,
        '192.166.222.222': 1
    }

    create_email_domain_chart(emails)
    create_ip_address_chart(ip_addresses)

if __name__ == '__main__':
    main()