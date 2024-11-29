
# create a config.txt file and write the configuration to it
config_template = '''f 1
%s:12345
%s:12345
%s:12345'''

def write_config(ip1, ip2, ip3):
    with open("config.txt", "w") as f:
        f.write(config_template % (ip1, ip2, ip3))


template = '''const char *eths[FAST_REPLICA_MAX] = {"9c:dc:71:56:8f:45",
										"9c:dc:71:56:bf:45", 
										"9c:dc:71:5e:2f:51", 
										"", 
										""};'''
new_string = '''
const char *eths[FAST_REPLICA_MAX] = {"%s",
                                        "%s", 
                                        "%s", 
                                        "", 
                                        ""};
'''
# find the given template in the config file and replace it with the new template
def update_mac(mac1, mac2, mac3):
    with open("xdp-handler/fast_user.c", "r") as f:
        s = f.read()
        s = s.replace(template, new_string % (mac1, mac2, mac3))
    print(s.split("\n")[1])
    with open("xdp-handler/fast_user.c", "w") as f:
        f.write(s)

if __name__ == "__main__":
    ips = "ip1, ip2, ip3".split(", ")
    macs = "mac1, mac2, mac3".split(", ")

    write_config(*ips)
    update_mac(*macs)


