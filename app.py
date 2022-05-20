from web.models import User
from web import APP, DB

def CreateDatabase():
    '''创建数据库'''
    DB.create_all()


def DeletDb():
    '''重置数据库'''
    DB.drop_all()
    CreateDatabase()

def bayonet_main():
    # DeletDb()
    CreateDatabase()
    # CreateUser()
    APP.run(host='0.0.0.0', port=APP.config['PORT'])
    #APP.run(port=APP.config['PORT'])

if __name__ == '__main__':
    #DeletDb()
    bayonet_main()