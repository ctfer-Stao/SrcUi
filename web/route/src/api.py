from flask_restful import reqparse, Resource
from flask import session, escape, json

from web import DB
from web.utils.auxiliary import addlog
from web.models import SrcDomain, SrcSubDomain, SrcPorts, SrcUrls, SrcVulnerabilitie, SrcWeb, SrcVuln
from web.utils.logs import logger

class SrcDomainAPI(Resource):
    '''src 主域名任务管理类'''

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("domain", type=str, location='json')
        self.parser.add_argument("domain_name", type=str, location='json')
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def post(self):
        '''添加任务'''
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_domain = args.domain.replace('/', '')
        key_domain_name = args.domain_name
        if not key_domain or not key_domain_name:
            return {'result': {'status_code': 500}}
        src_query = SrcDomain.query.filter(SrcDomain.domain == key_domain).first()
        if src_query:  # 已经存在domain任务
            addlog(session.get('username'), session.get('login_ip'),
                   f'添加主域名任务失败，主域名为：{key_domain},厂商为:{key_domain_name},原因:该任务已存在')
            return {'result': {'status_code': 201}}
        print(key_domain_name)
        SrcDomain1 = SrcDomain(domain=key_domain, domain_name=key_domain_name)
        DB.session.add(SrcDomain1)
        try:
            DB.session.commit()
        except Exception as e:
            logger.log('ALERT', '主域名添加任务接口SQL错误:%s' % e)
            DB.session.rollback()
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'添加主域名任务成功，主域名为：{key_domain},厂商为:{key_domain_name}')
        logger.log('INFOR', f'添加主域名任务成功-主域名[{key_domain}]-厂商[{key_domain_name}]')
        return {'result': {'status_code': 200}}

    def get(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcDomain.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcDomain.query.limit(20).offset(0).all()
            else:
                paginate = SrcDomain.query.limit(key_limit).offset((key_page - 1) * key_limit).all()
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcDomain.query.limit(20).offset(0).all()
            else:
                if 'domain' not in search_dict or 'domain_name' not in search_dict:  # 查询参数有误
                    paginate = SrcDomain.query.limit(20).offset(0).all()
                else:
                    paginate1 = SrcDomain.query.filter(
                        SrcDomain.domain.like("%" + search_dict['domain'] + "%"),
                        SrcDomain.domain_name.like("%" + search_dict['domain_name'] + "%"))
                    paginate = paginate1.limit(key_limit).offset((key_page - 1) * key_limit).all()
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {}
                data1['id'] = index
                data1['domain'] = i.domain
                data1['domain_name'] = i.domain_name
                data1['domain_time'] = i.domain_time
                data1['flag'] = i.flag
                subdomain_count = 0
                data1['subdomain_count'] = subdomain_count
                if subdomain_count > 0:
                    tmplist = i.src_subdomain
                    data1['ip_count'] = len(tmplist)
                    scan_count = 0
                    cdn_count = 0
                    for tmp in tmplist:
                        if not tmp.flag:
                            scan_count += 1
                        if tmp.cdn:
                            cdn_count += 1
                    data1['scan_count'] = scan_count
                    data1['cdn_count'] = cdn_count
                else:
                    data1['ip_count'] = 0
                    data1['scan_count'] = 0
                    data1['cdn_count'] = 0
                index += 1
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_domain = args.domain
        domain_query = SrcDomain.query.filter(SrcDomain.domain == key_domain).first()
        if not domain_query:  # 删除的domain不存在
            return {'result': {'status_code': 202}}
        DB.session.delete(domain_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'删除主任务失败,{e}')
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'删除主任务:[{key_domain}] 成功')
        logger.log('INFOR', f'删除主任务成功，{key_domain}')
        return {'result': {'status_code': 200}}

    def put(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_domain = args.domain
        domain_query = SrcDomain.query.filter(SrcDomain.domain == key_domain).first()
        if not domain_query:  # 删除的domain不存在
            return {'result': {'status_code': 202}}
        domain_query.flag = 'null'
        DB.session.add(domain_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'再次扫描主任务失败,{e}')
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'再次扫描主任务:[{key_domain}] 成功')
        logger.log('INFOR', f'再次扫描主任务成功，{key_domain}')
        return {'result': {'status_code': 200}}

class SrcPortsAPI(Resource):
    '''src 端口管理类'''

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcPorts.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcPorts.query.limit(20).offset(0).all()
            else:
                paginate = SrcPorts.query.limit(key_limit).offset((key_page - 1) * key_limit).all()
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcPorts.query.limit(20).offset(0).all()
            else:
                if 'subdomain' not in search_dict or 'product' not in search_dict:  # 查询参数有误
                    paginate = SrcPorts.query.limit(20).offset(0).all()
                else:
                    paginate1 = SrcPorts.query.filter(
                        SrcPorts.subdomain.like("%" + search_dict['subdomain'] + "%"),
                        SrcPorts.product.like("%" + search_dict['product'] + "%"))
                    paginate = paginate1.limit(key_limit).offset((key_page - 1) * key_limit).all()
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {}
                data1['id'] = index
                data1['subdomain'] = i.subdomain
                data1['subdomain_ip'] = i.subdomain_ip
                data1['port'] = i.port
                data1['service'] = i.service
                data1['product'] = i.product
                data1['version'] = i.version
                data1['porttime'] = i.port_time
                data1['city'] = i.src_subdomain.city
                index += 1
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

class SrcSubDomainAPI(Resource):
    '''src 子域名管理类'''

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcSubDomain.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcSubDomain.query.limit(20).offset(0).all()
            else:
                paginate = SrcSubDomain.query.limit(key_limit).offset((key_page - 1) * key_limit).all()
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcSubDomain.query.limit(20).offset(0).all()
            else:
                if 'subdomain' not in search_dict or 'subdomain_ip' not in search_dict:  # 查询参数有误
                    paginate = SrcSubDomain.query.limit(20).offset(0).all()
                else:
                    paginate1 = SrcSubDomain.query.filter(
                        SrcSubDomain.subdomain.like("%" + search_dict['subdomain'] + "%"),
                        SrcSubDomain.subdomain_ip.like("%" + search_dict['subdomain_ip'] + "%"))
                    paginate = paginate1.limit(key_limit).offset((key_page - 1) * key_limit).all()
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {}
                data1['id'] = index
                data1['domain'] = i.domain_name
                data1['subdomain'] = i.subdomain
                data1['domain_ip'] = i.subdomain_ip
                data1['cdn'] = i.cdn
                data1['domian_time'] = i.subdomain_time
                index += 1
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

class SrcUrlsAPI(Resource):
    '''src url扫描任务管理类'''

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)
        self.parser.add_argument("url_time", type=str, location='json')
        self.parser.add_argument("urls", type=str, location='json')

    def get(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcWeb.query.count()
        print(count)
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcWeb.query.limit(20).offset(0).all()
            else:
                paginate = SrcWeb.query.limit(key_limit).offset((key_page - 1) * key_limit).all()
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcWeb.query.limit(20).offset(0).all()
            else:
                if 'subdomain' not in search_dict or 'url' not in search_dict:  # 查询参数有误
                    paginate = SrcWeb.query.limit(20).offset(0).all()
                else:
                    paginate1 = SrcWeb.query.filter(
                        SrcWeb.domain_name.like("%" + search_dict['subdomain'] + "%"),
                        SrcWeb.url.like("%" + search_dict['url'] + "%"))
                    paginate = paginate1.limit(key_limit).offset((key_page - 1) * key_limit).all()
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {}
                data1['id'] = index
                data1['subdomain'] = i.domain_name
                data1['url'] = i.url
                data1['title'] = i.title
                data1['dir'] = i.dir
                data1['status'] = i.status
                data1['url_time'] = i.url_time
                index += 1
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_time = args.url_time
        url_query = SrcUrls.query.filter(SrcUrls.url_time == key_time).first()
        if not url_query:  # 删除的url不存在
            return {'result': {'status_code': 202}}
        DB.session.delete(url_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'删除URL任务失败,{e}')
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'删除URL任务成功')
        logger.log('INFOR', f'删除URL任务成功')
        return {'result': {'status_code': 200}}

    def post(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_time = args.url_time
        url_query = SrcUrls.query.filter(SrcUrls.url_time == key_time).first()
        if not url_query:  # 添加的url不存在
            return {'result': {'status_code': 202}}
        url_query.flag = True
        url_query.reptile = True
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'添加URL扫描任务失败,{e}')
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'添加URL扫描任务成功')
        logger.log('INFOR', f'添加URL扫描任务成功')
        return {'result': {'status_code': 200}}

    def put(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_scan_dict = args.urls.replace("'", '"')
        try:
            key_scan_dict = json.loads(key_scan_dict)
        except:
            return {'result': {'status_code': 500}}
        for key, value in key_scan_dict.items():
            url_query = SrcUrls.query.filter(SrcUrls.url_time == key_scan_dict[key]['time']).first()
            if not url_query:
                continue
            else:
                url_query.flag = True
                url_query.reptile = True
                DB.session.add(url_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'批量添加URL任务失败,{e}')
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'批量添加URL任务成功')
        logger.log('INFOR', f'批量添加URL任务成功')
        return {'result': {'status_code': 200}}

class SrcUrls1API(Resource):
    '''src url管理类'''

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcWeb.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcWeb.query.limit(20).offset(0).all()
            else:
                paginate = SrcWeb.query.limit(key_limit).offset((key_page - 1) * key_limit).all()
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcWeb.query.limit(20).offset(0).all()
            else:
                if 'subdomain' not in search_dict or 'url' not in search_dict:  # 查询参数有误
                    paginate = SrcWeb.query.limit(20).offset(0).all()
                else:
                    paginate1 = SrcWeb.query.filter(
                        SrcWeb.domain_name.like("%" + search_dict['subdomain'] + "%"),
                        SrcWeb.url.like("%" + search_dict['url'] + "%"))
                    paginate = paginate1.limit(key_limit).offset((key_page - 1) * key_limit).all()
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {}
                data1['id'] = index
                data1['subdomain'] = i.domain_name
                data1['url'] = i.url
                data1['title'] = i.title
                data1['dir'] = i.dir
                data1['status'] = i.status
                data1['url_time'] = i.url_time
                index += 1
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

class SrcScanAPI(Resource):
    '''src 漏洞管理类'''

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)
        self.parser.add_argument("time", type=str)
        self.parser.add_argument("scan", type=str, location='json')

    def get(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcVuln.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcVuln.query.paginate(1, 20, False).items
            else:
                paginate = SrcVuln.query.paginate(key_page, key_limit, False).items
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcVuln.query.paginate(1, 20, False).items
            else:
                if 'plugin' not in search_dict or 'url' not in search_dict:  # 查询参数有误
                    paginate = SrcVuln.query.paginate(key_page, key_limit, False).items
                else:
                    paginate1 = SrcVuln.query.filter(
                        SrcVuln.src_name.like("%" + search_dict['plugin'] + "%"),
                        SrcVuln.url.like("%" + search_dict['url'] + "%"))
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
                    paginate = paginate1.paginate(key_page, key_limit, False).items

        data = []
        if paginate:
            for i in paginate:
                data1 = {}
                data1['url'] = i.url
                data1['severity'] = i.severity
                data1['name'] = i.src_name
                data1['scan_name'] = i.vuln_name
                data1['time'] = i.vuln_time
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def post(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_time = args.time
        scan_query = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.time == key_time).first()
        if not scan_query:
            return {'result': {'status_code': 500}}
        scan_query.flag = True
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'提交漏洞失败,{e}')
            return {'result': {'status_code': 500}}
        return {'result': {'status_code': 200}}

    def delete(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_time = args.time
        scan_query = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.time == key_time).first()
        if not scan_query:
            return {'result': {'status_code': 500}}
        DB.session.delete(scan_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'删除漏洞失败,{e}')
            return {'result': {'status_code': 500}}
        return {'result': {'status_code': 200}}

    def put(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_scan_dict = args.scan.replace("'", '"')
        try:
            key_scan_dict = json.loads(key_scan_dict)
        except:
            return {'result': {'status_code': 500}}
        for key, value in key_scan_dict.items():
            url_query = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.time == key_scan_dict[key]['time']).first()
            if not url_query:
                continue
            else:
                DB.session.delete(url_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'批量删除漏洞任务失败,{e}')
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'批量删除漏洞任务成功')
        logger.log('INFOR', f'批量删除漏洞任务成功')
        return {'result': {'status_code': 200}}

class SrcScanSuccessAPI(Resource):
    '''src 已提交漏洞管理类'''

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)
        self.parser.add_argument("time", type=str)

    def get(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == True).count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == True).paginate(1, 20, False).items
            else:
                paginate = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == True).paginate(key_page, key_limit, False).items
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == True).paginate(1, 20, False).items
            else:
                if 'plugin' not in search_dict or 'url' not in search_dict:  # 查询参数有误
                    paginate = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == True).paginate(key_page, key_limit, False).items
                else:
                    paginate1 = SrcVulnerabilitie.query.filter(
                        SrcVulnerabilitie.plugin.like("%" + search_dict['plugin'] + "%"),
                        SrcVulnerabilitie.url.like("%" + search_dict['url'] + "%"), SrcVulnerabilitie.flag == True)
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
                    paginate = paginate1.paginate(key_page, key_limit, False).items

        data = []
        if paginate:
            for i in paginate:
                data1 = {}
                data1['id'] = i.id
                data1['subdomain'] = i.subdomain
                data1['plugin'] = i.plugin
                data1['url'] = i.url
                data1['payload'] = i.payload
                data1['raw'] = i.raw.replace('\n', '<br/>')
                data1['scan_name'] = i.scan_name
                data1['time'] = i.time
                flag = '未提交'
                if i.flag:
                    flag = '已提交'
                data1['flag'] = flag
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_time = args.time
        scan_query = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.time == key_time).first()
        if not scan_query:
            return {'result': {'status_code': 500}}
        DB.session.delete(scan_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'删除漏洞失败,{e}')
            return {'result': {'status_code': 500}}
        return {'result': {'status_code': 200}}
