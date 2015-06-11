#!py

import re
import yaml
from collections import OrderedDict
from salt.utils.validate.net import ipv4_addr, ipv6_addr

ipv4_re = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
ipv6_re = re.compile('^(((?=.*(::))(?!.*\3.+\3))\3?|[\dA-F]{1,4}:)([\dA-F]{1,4}(\3|:\b)|\2){5}(([\dA-F]{1,4}(\3|:\b|$)|\2){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})\Z', re.I|re.S)

def pkgs(pkg_defaults):
  pkgs = __salt__['grains.filter_by'](pkg_defaults)
  return pkgs

def load_defaults():
  #with open('iptables/defaults.yaml') as defaults_file:
  __salt__['cp.cache_file']('salt://iptables/defaults.yaml')
  with open('defaults.yaml') as defaults_file:
    defaults = yaml.load(defaults_file)
  defaults.update({'pkgs': __salt__['grains.filter_by'](defaults.get('pkgs'))})
  return defaults

def str2list(param):
  if type(param) == type(''):
    return [param]
  return param

def dict2state(config):
  rule = []
  for k, v in config.iteritems():
    rule.append( {k: v} )
  return rule

def state2dict(config):
  rule = OrderedDict()
  for option in config:
    rule.update(option)
  return rule

def getFamily(config):
  family = str2list(config.pop('family', []))

  source_list = str2list(config.pop('source',[])) 
  source_list.extend( str2list(config.get('ips_allow',[])) ) #backward compability
  source_list = {}.fromkeys(source_list).keys()  # make keys uniq

  if family:
    return family
  if not source_list:
    family = ['ipv4', 'ipv6']
  #elif [ ip for ip in source_list if re.search(ipv4_re, ip) ]:
  elif [ ip for ip in source_list if ipv4_addr(ip) ]:
    family = ['ipv4']
  #elif [ ip for ip in source_list if re.search(ipv6_re, ip) ]:
  elif [ ip for ip in source_list if ipv6_addr(ip) ]:
    family = ['ipv6']
  else:
    family = ['fucked']
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
  policy = OrderedDict()
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
    policy[family + 'tables_FORWARD_allow_state'] = {
      'iptables.insert': accept(FORWARD(family,[
        {'position': 1},
        {'match': 'state'},
        {'connstate': 'RELATED,ESTABLISHED'}
      ]))
    }
    policy[family + 'tables_forward_policy'] = {
      'iptables.set_policy':[
        {'family': family},
        {'table': 'filter'},
        {'chain': 'FORWARD'},
        {'policy': 'DROP'},
        {'require':[
          {'iptables': family + 'tables_FORWARD_allow_state'}
        ]}
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
  service = OrderedDict()

  strict = __salt__['pillar.get']('firewall:strict', False)
  if config == True:
    config = {}
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
        if name != dport: id_name = name + '_on_port_' + str(dport)
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


def custom_rules(name, config, suffix=''):
  rules_list=[]
  rules = OrderedDict()
  config.update({'table': config.get('table', 'filter')})
  action = config.pop('action', 'append').lower()
  chain_name = config.get('chain')
  if suffix:
    config.update({'chain': config['chain'].lower() + suffix})
  for family in getFamily(config):
    config.update({'family': family})
    rules_list.append(config.copy())
  for rule in rules_list:
    family = rule['family']
    rules[family + 'tables_' + rule['table'] + '_' + chain_name + '_' + name + '_' + rule['jump'] ] = {
      'iptables.' + action: dict2state(rule)
    }
  return rules

def whitelist_rules(name, config, suffix=''):
  rules=OrderedDict()

  for family in getFamily(config):
    for ip in str2list(config.get('ips_allow',[])):
      rules[family + 'tables_whitelist_' + name + '_allow_' + ip] = {
          'iptables.append': accept(custom_chain(family,'input' + suffix,
            dict2state({'source': ip})
          ))
      }

  return rules

def flush_fw(family=['ipv4', 'ipv6'], table=['filter', 'nat', 'mangle', 'raw'], chain='', args=[]):
  family=str2list(family)
  table=str2list(table)
  rules = OrderedDict()
  for f in family:
    for t in table:
      if chain:
        rule_id = f +  'tables_' + t + '_' + chain + '_flush'
        rule = [
            {'table': t},
            {'family': f},
            {'chain': chain}
        ]
      else:
        rule_id = f+'tables_' + t +'_flush'
        rule = [
            {'table': t},
            {'family': f}
        ]
      rule.extend(args)
      rules.update({rule_id:{
        'iptables.flush': rule}
        })
  return rules

def install_chains(*chains, **kwargs):
  suffix = kwargs['suffix']
  flush = kwargs['flush']
  rules = OrderedDict()
  for family, table, chain in chains:
    if family == 'all':
      families=['ipv4', 'ipv6']
    else:
      families = str2list(family)
    if table == 'all':
      tables = ['filter', 'nat', 'mangle', 'raw']
    else:
      tables = str2list(table)
    chain = chain.lower() + suffix
    for family in families:
      for table in tables:
        rules[family + 'tables_'+ table + '_' + chain + '_chain'] = {
          'iptables.chain_present':[
            {'name': chain},
            {'table': table},
            {'family': family},
          ]
        }
        if flush:
          rules.update(flush_fw(family, table, chain))
        rules[family + 'tables_'+ table + '_' + chain + '_in']={
          'iptables.append': [
            {'family': family},
            {'table': table},
            {'chain': chain.replace(suffix,'').upper()},
            {'jump': chain},
            {'require':[
              {'iptables': family + 'tables_'+ table + '_' + chain + '_chain'}
            ]}
          ]
        }
  return rules


def return_rules(*chains, **kwargs):
  suffix = kwargs['suffix']
  rules = OrderedDict()
  for family, table, chain in chains:
    if family == 'all':
      families=['ipv4', 'ipv6']
    else:
      families = str2list(family)
    if table == 'all':
      tables = ['filter', 'nat', 'mangle', 'raw']
    else:
      tables = str2list(table)
    chain = chain.lower() + suffix
    for family in families:
      for table in tables:
        rules[family + 'tables_'+ table + '_' + chain + '_return']={
          'iptables.append': [
            {'family': family},
            {'table': table},
            {'chain': chain},
            {'jump': 'RETURN'},
          ]
        }
  return rules

def service_chain(services):
  rules = OrderedDict()
  chain_name = 'inputSERVICES'
  suffix= 'SERVICES'
  flush = services.pop('flush', False)
  chains = [('all', 'filter', 'INPUT')]
  rules.update(install_chains(suffix=suffix,flush=flush, *chains))
  for service_name, service_details in services.items():
    rules.update(service_rules(service_name, service_details, chain=chain_name))
  rules.update(return_rules(suffix=suffix, *chains))

  return rules  

def customrules_chain(custom):
  rules = OrderedDict()
  suffix = 'CUSTOM'
  flush = custom.pop('flush', False)
  #         family, table,  chain
  chains = [('all', ['filter', 'nat', 'mangle'], 'INPUT'),
            ('all', ['filter', 'nat', 'mangle', 'raw'], 'OUTPUT'),
            ('all', ['filter', 'mangle'], 'FORWARD'),
            ('all', ['nat', 'mangle'], 'POSTROUTING'),
            ('all', ['nat', 'mangle', 'raw'], 'PREROUTING'),
           ]
  rules.update(install_chains( *chains, suffix=suffix, flush=flush))
  for name, details in custom.items():
    rules.update(custom_rules(name, details, suffix=suffix))
  rules.update(return_rules(suffix=suffix, *chains))
  return rules

def whitelist_chain(whitelist):
  rules = OrderedDict()
  suffix='WHITELIST'
  flush = whitelist.pop('flush', False)
  chains = [('all', 'filter', 'INPUT'),
            ('all', 'filter', 'FORWARD')
           ]
  rules.update(install_chains(suffix=suffix,flush=flush, *chains))
  for name, details in whitelist.items():
    rules.update(whitelist_rules(name, details, suffix=suffix))
  rules.update(return_rules(suffix=suffix, *chains))

  return rules

def run():
  config = OrderedDict()
  defaults = load_defaults()
  if not __salt__['pillar.get']('firewall:enabled'):
    return config

  firewall = __salt__['pillar.get']('firewall', {})
  firewallGrain = __salt__['grains.get']('firewall',[])
  firstrun = False
  strict = firewall.get('strict', defaults.get('strict'))
  if firewall.get('install', defaults.get('install')):
    config['install_packages'] = {
        'pkg.installed':[
          {'pkgs': defaults.get('pkgs')},
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
  # Flush firewall in firstrun
  if firewall.get('flushfirstrun', defaults.get('flushfirstrun')) and 'managed' not in firewallGrain:
    firstrun = True
    __salt__['grains.append']('firewall', 'managed')
  if firewall.get('flush', defaults.get('flush')) or firstrun:
    config.update(flush_fw())
  config.update(load_policy(strict))
  config.update(whitelist_chain(
      firewall.get('whitelist', {})
    ))
  config.update(customrules_chain(
      firewall.get('custom', {})
    ))
  config.update(service_chain(
      firewall.get('services', {})
    ))
  for service_name, service_details in firewall.get('nat', {}).items():
    config.update(nat_rules(service_name, service_details))
  return config

