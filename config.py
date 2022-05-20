import uuid
import os
import pathlib
import urllib3

class BayonetConfig(object):
    '''Flask数据配置'''
    SECRET_KEY = str(uuid.uuid4())
    # SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:123456@127.0.0.1/bayonet?charset=utf8'  # 数据库连接字符串
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:hxz1314520@127.0.0.1/bayonet?charset=utf8'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TITLE = '挖掘机 资产管理系统'
    PORT = 8080  # web端口

