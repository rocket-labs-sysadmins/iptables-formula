#!py

import re

ipv4_re = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}")
ipv6_re = re.compile('^(((?=.*(::))(?!.*\3.+\3))\3?|[\dA-F]{1,4}:)([\dA-F]{1,4}(\3|:\b)|\2){5}(([\dA-F]{1,4}(\3|:\b|$)|\2){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})\Z', re.I|re.S)

def __pkgs():
  pkgs = __salt__['grains.filter_by']({
    'Debian': ['iptables', 'iptables-persistent'],
    'RedHat': ['iptables', 'iptables-services'],
    'default': 'RedHat'
  })
  return pkgs


def str2list(param):
  if type(param) == type(''):
    return [param]
  return param

def dict2state(config):
  rule = []
  for k, v in config.items():
    rule.append( {k: v} )
  return rule

def getFamily(config):
  family = str2list(config.pop('family', []))
  if family:
    return family
  if not config.get('source', []):
    family = ['ipv4', 'ipv6']
  elif [ ip for ip in str2list(config.get('source')) if re.search(ipv4_re, ip) ]:
    family = ['ipv4']
  elif [ ip for ip in str2list(config.get('source')) if re.search(ipv6_re, ip) ]:
    family = ['ipv6']
  return family


def custom_chain(family, chain, args=[]):
  ch = [
    {'family': family},
    {'table': 'filter'},
    {'chain': chain}
  ]
  ch.extend(args)
  return ch

def INPUT(family, args=[]):
  return custom_chain(family, 'INPUT', args)

def FORWARD(family, args=[]):
  chain = [
    {'family': family},
    {'table': 'filter'},
    {'chain': 'FORWARD'}
  ]
  chain.extend(args)
  return chain

def OUTPUT(family, args=[]):
  chain = [
    {'family': family},
    {'table': 'filter'},
    {'chain': 'OUTPUT'}
  ]
  chain.extend(args)
  return chain


def accept(args=[]):
  action = [
      {'jump': 'ACCEPT'},
      {'save': True}
  ]
  action.extend(args)
  return action

def drop(args=[]):
  action = [
      {'jump': 'DROP'},
      {'save': True}
  ]
  action.extend(args)
  return action


def load_policy(strict = False):
  if not strict:
    return {}
  policy = {}
  for family in ['ipv4', 'ipv6']:
    policy[family + 'tables_INPUT_allow_lo'] = {
      'iptables.append': accept(INPUT(family,[
        {'i': 'lo'},
        {'match': [
          'comment'
        ]},
        {'comment': "Allow on Loopback"},
        {'require': [
          {'iptables': family + 'tables_INPUT_allow_state'}
        ]}
      ]))
    }
    policy[family + 'tables_INPUT_allow_state'] = {
      'iptables.insert': accept(INPUT(family,[
        {'position': 1},
        {'match': 'state'},
        {'connstate': 'RELATED,ESTABLISHED'}
      ]))
    }
    policy[family + 'tables_INPUT_policy'] = {
      'iptables.set_policy':[
        {'family': family},
        {'table': 'filter'},
        {'chain': 'INPUT'},
        {'policy': 'DROP'},
        {'require':[
          {'iptables': family + 'tables_INPUT_allow_lo'},
          {'iptables': family + 'tables_INPUT_allow_state'}
        ]}
      ]
    }
    policy[family + 'tables_forward_policy'] = {
      'iptables.set_policy':[
        {'family': family},
        {'table': 'filter'},
        {'chain': 'FORWARD'},
        {'policy': 'DROP'}
      ]
    }
    policy[family + 'tables_output_policy'] = {
      'iptables.set_policy':[
        {'family': family},
        {'table': 'filter'},
        {'chain': 'OUTPUT'},
        {'policy': 'ACCEPT'}
      ]
    }

  policy['ipv4tables_FORWARD_allow_state'] = {
    'iptables.insert': accept(FORWARD('ipv4',[
      {'position': 1},
      {'match': 'state'},
      {'connstate': 'RELATED,ESTABLISHED'}
    ]))
  }

  policy['ipv4tables_INPUT_icmp'] = {
    'iptables.append': accept(INPUT('ipv4',[
      {'protocol': 'icmp'}
    ]))
  }
  policy['ipv6tables_INPUT_icmp'] = {
    'iptables.append': accept(INPUT('ipv6',[
      {'protocol': 'icmpv6'}
    ]))
  }

  return policy


def service_rules(name, config, chain='INPUT'):
  service = {}

  strict = __salt__['pillar.get']('firewall:strict', False)

  block_nomatch = config.pop('block_nomatch', False)
  protos = str2list(config.pop('proto', ['tcp']))
  config['dport'] = str2list(config.pop('dport', [name]))
  source_list = str2list(config.pop('source',[])) 
  source_list.extend( str2list(config.pop('ips_allow',[])) ) #backward compability
  source_list = {}.fromkeys(source_list).keys()  # make keys uniq
  tmp_config = config.copy()
  config.update({'source': source_list})
  if  [name] == tmp_config['dport']:
    id_name = name
  #for family in str2list(config.pop('family', ['ipv4', 'ipv6'])):
  for family in getFamily(config):
    for proto in protos:
      tmp_config['proto'] = proto
      for dport in config['dport']:
        tmp_config['dport'] = dport
        if name != dport: id_name = name + '_on_port_' + dport
        allow_rule_id = family +'tables_' + id_name + '_allow'
        if source_list:
          for source_ip in source_list:
            tmp_config['source'] = source_ip
            service[ allow_rule_id + '_' + source_ip ] = {
              'iptables.append': accept(custom_chain(family, chain,
                dict2state(tmp_config)))
            }
        else:
          service[ allow_rule_id ] = {
            'iptables.append': accept(custom_chain(family, chain,
              dict2state(tmp_config)))
          }

        not_config = tmp_config.copy()
        if source_list and not strict and block_nomatch or __salt__['pillar.get']('firewall:block_nomatch', False):
          not_config.pop('source')
          rule = drop(custom_chain(family, chain,
                dict2state(tmp_config)))
          rule.append(
                  {'require': [
                    {'iptables': allow_rule_id}
                  ]}
                )
          service[family +'tables_' + id_name + '_deny_other'] = {
              'iptables.append': rule
          }

  return service

def nat_rules(name, config):
  rules={}
  for source, ip_d in config.pop('rules', {}).items():
    for dst in str2list(ip_d):
      rules['ip4tables_' + name + '_allow_' + source + '_' + dst] = {
        'iptables.append':[
          {'table': 'nat'},
          {'chain': 'POSTROUTING'},
          {'jump': 'MASQUERADE'},
          {'o': name},
          {'source': source},
          {'destination': dst},
          {'save': True}
        ]
      }
  return rules


def custom_rules(name, config):
  rules_list=[]
  rules={}
  config.update({'table': config.get('table', 'filter')})
  action = config.pop('action', 'append').lower()
  for family in getFamily(config):
    config.update({'family': family})
    rules_list.append(config.copy())
  for rule in rules_list:
    family = rule['family']
    rules[family + 'tables_' + rule['chain'] + '_' + name + '_' + rule['jump'] ] = {
      'iptables.' + action: dict2state(rule)
    }
  return rules

def whitelist_rules(name, config):
  rules={}
  for family in getFamily(config):
    for ip in config.get('ips_allow',[]):
      rules[family + 'tables_' + name + '_allow_' + ip] = {
          'iptables.append': accept(INPUT(family,
            dict2state({'source': ip})
          ))
      }

  return rules

def service_chain(services):
  chains={}
  rules = {}
  ret_rule = {}
  in_rule = {}
  for service_name, service_details in services.items():
    rules.update(service_rules(service_name, service_details, chain='inputSERVICES'))

  require = {'ipv6': [], 'ipv4': []}
  for rule_id in rules.keys():
    family = rule_id[:4]
    require[family].append({'iptables': rule_id})

  for family in ['ipv4', 'ipv6']:
    chains[family + 'tables_inputSERVICES_chain']={
      'iptables.chain_present':[
        {'name': 'inputSERVICES'},
        {'table': 'filter'},
        {'family': family},
        {'require_in': require[family]}
      ]
    }
    ret_rule[family + 'tables_inputSERVICES_return']={
      'iptables.append': [
        {'family': family},
        {'table': 'filter'},
        {'chain': 'inputSERVICES'},
        {'jump': 'RETURN'},
        {'require': require[family]}
      ]
    }
    in_rule[family + 'tables_inputSERVICES_in']={
      'iptables.append': [
        {'family': family},
        {'table': 'filter'},
        {'chain': 'INPUT'},
        {'jump': 'inputSERVICES'},
        {'require':[
          {'iptables': family + 'tables_inputSERVICES_chain'}
        ]}
      ]
    }

  rules.update(chains)
  rules.update(ret_rule)
  rules.update(in_rule)
  return rules  


def run():
  config = {}
  if not __salt__['pillar.get']('firewall:enabled'):
    return config

  firewall = __salt__['pillar.get']('firewall', {})
  strict = firewall.get('strict', False)
  
  if firewall.get('install', False):
    config['install_packages'] = {
        'pkg.installed':[
          {'pkgs': __pkgs()},
        ]
    }
    if __grains__['os_family'] == 'RedHat':
      for service in ['iptables', 'ip6tables']:
        config[ service + '_service' ] = {
          'service.running':[
            {'name': service},
            {'enable': True}
          ]
        }

  config.update(load_policy(strict))
  config.update(service_chain(firewall.get('services', {})))
  for service_name, service_details in firewall.get('nat', {}).items():
    config.update(nat_rules(service_name, service_details))
  for rule_name, rule_details in firewall.get('custom', {}).items():
    config.update(custom_rules(rule_name, rule_details))
  
  return config

