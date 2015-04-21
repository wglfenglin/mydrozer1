# __author__ = 'fenglin'
#-*- coding: utf-8 -*-
import MySQLdb
try:
    mydb = MySQLdb.connect(host='localhost', user='root', passwd='drozer', port=3306)
    mydb.select_db('drozer')
    mydb.autocommit(1)
    cursor = mydb.cursor()
                # text ="insert into exported_activities values('1','2')"
    cursor.execute("insert into exported_activities values('111','222');")
    cursor.execute("select * from exported_activities;")
    rows = cursor.fetchall()
    for row in rows:
        print row
    cursor.close()

    mydb.close()
except MySQLdb.Error, e:
    mydb.rollback()
    print "Mysql Error %d: %s" % (e.args[0], e.args[1])
    cursor.close()
    mydb.close()
print "hahah"