#-*- coding: UTF-8 -*-
import re
from PyQt4 import QtGui
import xml.etree.ElementTree as ET
from drozer import android
from drozer.modules import common, Module
from pydiesel.reflection import ReflectionException

class AttackSurface(Module, common.BusyBox, common.Shell, common.SuperUser, common.Filters, common.IntentFilter, common.PackageManager,common.Provider, common.ZipFile, common.Strings):
    name = "Get attack surface of package"
    description = "Examine the attack surface of an installed package."
    examples = """Finding the attack surface of the built-in browser

    dz> run app.package.attacksurface com.android.browser

    6 activities exported
    4 broadcast receivers exported
    1 content providers exported
    0 services exported"""
    author = "MWR InfoSecurity (@mwrlabs)"
    date = "2012-11-06"
    license = "BSD (3 clause)"
    path = ["app", "package"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]
    # added
    attackable_activities = []
    attackable_receivers = []
    attackable_services = []
    attackable_providers = []
    attackable_package_name = ''
    debuggable = False
    sharedUID = 0
    # added
    def add_arguments(self, parser):
        parser.add_argument("package", help="the identifier of the package to inspect")

    def testcontext(self):
        context= self.getContext().getClass().getDeclaredMethods()

        print

    def execute(self, arguments, myui):
        self.ui = myui
        """
        :param arguments:
        :return
        """
        # self.testcontext()


        if arguments.package != None:
            package = self.packageManager().getPackageInfo(arguments.package,
                                                           common.PackageManager.GET_ACTIVITIES | common.PackageManager.GET_RECEIVERS | common.PackageManager.GET_PROVIDERS | common.PackageManager.GET_SERVICES)
            application = package.applicationInfo

            self.attackable_package_name= package.packageName
            if (application.flags & application.FLAG_DEBUGGABLE) != 0:
                self.debuggable = True

                self.stdout.write("    is debuggable\n")
            if package.sharedUserId != None:
                self.stdout.write("    Shared UID (%s)\n" % package.sharedUserId)
                self.sharedUID = package.sharedUserId

            activities = self.match_filter(package.activities, 'exported', True)
            receivers = self.match_filter(package.receivers, 'exported', True)
            services = self.match_filter(package.services, 'exported', True)
            providers = self.match_filter(package.providers, 'authority', True)
            r_providers = self.match_filter(providers, 'readPermission', True)
            w_providers = self.match_filter(providers, 'writePermission', True)
            providers = set(r_providers + w_providers)
            # providers = self.match_filter(providers, 'exported', True)
            '''
            added
            '''
            self.attackable_activities = self.match_filter(activities, 'permission', 'null')
            self.attackable_services = self.match_filter(services, 'permission', 'null')
            self.attackable_providers = providers
            self.attackable_receivers = self.match_filter(receivers, 'permission', 'null')



            self.scanComponents(package)
            # self.scanNatives(package)
            # self.scanWorldRWFiles(application)
            # self.scan_vulnerable_uris(self.attackable_package_name)
            self.scan_webview()
            '''
            added
            '''

        else:
            self.stdout.write("No package specified\n")

    def findBrowserableActivity(self, package):
        names1 = []
        names2= []
        manifest = self.getAndroidManifest(package)
        root = ET.fromstring(manifest)
        for activity in root.find('application').findall('activity'):
            for intentfilter in activity.findall('intent-filter'):
                foundBrowsable = False
                category = intentfilter.findall('category')
                for cat in category:
                    if cat.get('name') == "android.intent.category.BROWSABLE":
                        foundBrowsable = True
                if foundBrowsable:
                    name = activity.get('name')
                    if not name in names1:
                        names1.append(name)
        for activity in self.attackable_activities:
            if (activity.name in names1) and (not activity.name in names2):
                names2.append(activity)

        return names2

    def scanComponents(self, package):
        sql = "insert into exported_activities values('"

        '''
        scan attack_activities
        '''
        if len(self.attackable_activities) > 0:
            for attack_activity in self.attackable_activities:
                intent_filters = self.find_intent_filters(attack_activity, 'activity')
                if len(intent_filters) > 0:
                    self.sqlstdout.write("insert into exported_activities values('%s','%s',1);"
                                         % (self.attackable_package_name, attack_activity.name)
                    )
                    for intent_filter in intent_filters:
                        self.startWithIntent(attack_activity,intent_filter)
                        self.insert_with_intent(attack_activity, intent_filter, 'activity_intent')
                else:
                    self.sqlstdout.write("insert into exported_activities values('%s','%s',0);"
                                         % (self.attackable_package_name, attack_activity.name)
                    )
                    # self.startWithNull(attack_activity)

        self.ui.progressBar.setProperty("value", 25)
        QtGui.QApplication.processEvents()
        '''
        scan attack_services
        '''
        if len(self.attackable_services) > 0:
            for attack_service in self.attackable_services:
                intent_filters = self.find_intent_filters(attack_service, 'service')
                if len(intent_filters) > 0:
                    self.sqlstdout.write("insert into exported_services values('%s','%s',1);"
                                         % (self.attackable_package_name, attack_service.name)
                    )
                    for intent_filter in intent_filters:
                        self.insert_with_intent(attack_service, intent_filter, 'service_intent')
                else:
                    self.sqlstdout.write("insert into exported_services values('%s','%s',0);"
                                         % (self.attackable_package_name, attack_service.name)
                    )
        self.ui.progressBar.setProperty("value", 50)
        QtGui.QApplication.processEvents()
        '''
        scan exported_receivers
        '''
        if len(self.attackable_receivers) > 0:
            for attack_receiver in self.attackable_receivers:
                intent_filters = self.find_intent_filters(attack_receiver, 'receiver')
                if len(intent_filters) > 0:
                    self.sqlstdout.write("insert into exported_receivers values('%s','%s',1);"
                                         % (self.attackable_package_name, attack_receiver.name)
                    )
                    for intent_filter in intent_filters:
                        self.insert_with_intent(attack_receiver, intent_filter, 'receiver_intent')
                else:
                    self.sqlstdout.write("insert into exported_receivers values('%s','%s',0);"
                                         % (self.attackable_package_name, attack_receiver.name)
                    )
        self.ui.progressBar.setProperty("value", 75)
        QtGui.QApplication.processEvents()
        '''
        scan exported_providers
        '''
        if len(self.attackable_providers) > 0:
            for attack_provider in self.attackable_providers:
                self.sqlstdout.write("insert into exported_providers values('%s','%s');"
                                     % (self.attackable_package_name, attack_provider.name)
                )
                self.scan_exported_provider(attack_provider)
        self.ui.progressBar.setProperty("value", 100)
        QtGui.QApplication.processEvents()

    def scan_vulnerable_uris(self, package):
        """
        find uris in the given package that can be injected and traveraled
        :param package: string ==package.packageName
        :var sql1 traversal sql
        :var sql2 injection sql
        """
        sql1 = ""

        vulnerable_uris = {"traversal_uris": [], "injection_uris": []}
        for uri in self.findAllContentUris(package):
            """
             traversal
             """
            try:
                data = self.contentResolver().read(uri + "/../../../../../../../../../../../../../../../../etc/hosts")
            except ReflectionException as e:
                if e.message.find("java.io.FileNotFoundException") >= 0 or \
                                e.message.find("java.lang.IllegalArgumentException") >= 0 or \
                                e.message.find("java.lang.SecurityException") >= 0 or \
                                e.message.find("No content provider") >= 0 or \
                        e.message.find("RuntimeException"):
                    data = ""
                else:
                    raise
            if data != None and len(data) > 0:
                vulnerable_uris["traversal_uris"].add(uri)

            """
            injection
            """
            try:
                self.contentResolver().query(uri, projection=["'"])
            except ReflectionException as e:
                if e.message.find("unrecognized token") >= 0:
                    vulnerable_uris["injection_uris"].add(uri)

            try:
                self.contentResolver().query(uri, selection="'")
            except ReflectionException as e:
                if e.message.find("unrecognized token") >= 0:
                    vulnerable_uris["injection_uris"].add(uri)

            if 0 != len(vulnerable_uris["traversal_uris"]):
                for traversal_uri in vulnerable_uris["traversal_uris"]:
                    self.sqlstdout.write("insert into traversal_uris values('%s', '%s');" % (package, traversal_uri))
            if 0 != len(vulnerable_uris["injection_uris"]):
                for injection_uri in vulnerable_uris["injection_uris"]:
                    self.sqlstdout.write("insert into injection_uris values('%s', '%s');" % (package, injection_uri))

    def scanNatives(self, package):
        Native = self.loadClass("common/Native.apk", "Native")
        sqlsentence = "insert into nativies values('%s','%s','%s')"
        self.bundled_libraries = Native.list(package.applicationInfo)
        self.shared_libraries = package.applicationInfo.sharedLibraryFiles
        for bundled_library in self.bundled_libraries:
            self.sqlstdout.write(sqlsentence % (self.attackable_package_name, bundled_library, "bundled_library"))
        for shared_library in self.shared_libraries:
            self.sqlstdout.write(sqlsentence % (self.attackable_package_name, shared_library, "shared_library"))

    def scanWorldRWFiles(self, application):

        DataDir = application.dataDir
        if self.isBusyBoxInstalled():
            command = self.busyboxPath() + " find %s \( -type b -o -type c -o -type f -o -type s \) -perm -o=r \-exec ls {} \;" % DataDir
            if self.isAnySuInstalled():
                command = self.suPath() + " -c \"%s\"" % command
            else:
                self.stdout.write("su is not installed...reverting back to unprivileged mode\n")
            files = self.shellExec(command)
            readable_files = []
            for f in iter(files.split("\n")):
                if not f.startswith('find: ') and len(f.strip()) > 0:
                    readable_files.append(f)
            if len(readable_files) > 0:
                self.stdout.write("Discovered world-readable files in %s:\n" % DataDir)
                for f in readable_files:
                    self.stdout.write("  %s\n" % f)

            command = self.busyboxPath() + " find %s \( -type b -o -type c -o -type f -o -type s \) -perm -o=w \-exec ls {} \;" % DataDir
            command = self.suPath() + " -c \"%s\"" % command
            files = self.shellExec(command)
            writable_files = []
            for f in iter(files.split("\n")):
                if not f.startswith('find: ') and len(f.strip()) > 0:
                    writable_files.append(f)

            if len(writable_files) > 0:
                self.stdout.write("Discovered world-writable files in %s:\n" % DataDir)
                for f in writable_files:
                    self.stdout.write("  %s\n" % f)
        else:
            self.stderr.write("This command requires BusyBox to complete. Run tools.setup.busybox and then retry.\n")

    def scan_exported_provider(self, provider):
        PatternMatcherTypes = {0: "PATTERN_LITERAL", 1: "PATTERN_PREFIX", 2: "PATTERN_SIMPLE_GLOB"}
        sqlsentence = "insert into provider_info values('%s','%b','%b','%s','%b','%s','%b','%b');"
        read_permission = provider.readPermission
        write_permission = provider.writePermission
        authority = provider.authority
        provider_name = provider.name
        multiprocess = provider.multiprocess
        grant_uri_permission = provider.grantUriPermissions
        if provider.uriPermissionPatterns != None:
            uri_permission_patterns = True
            for pattern in provider.uriPermissionPatterns:
                uri_path = pattern.getPath()
                uri_type = PatternMatcherTypes[int(pattern.getType())]
                self.sqlstdout.write("insert into uri_permission_patterns values('%s','%s','%s')"
                                     % (provider_name, uri_path, uri_type)
                )
        else:
            uri_permission_patterns = False
        if provider.pathPermissions != None:
            path_permission = True
            for permission in provider.pathPermissions:
                path = permission.getPath()
                path_type = PatternMatcherTypes[int(permission.getType())]
                path_read_permission = permission.getReadPermission()
                path_write_permission = permission.getWritePermission()
                self.sqlstdout.write("insert into path_permission values('%s','%s','%s','%s','%s')"
                                     % (provider_name, path, path_type, path_read_permission, path_write_permission))
        else:
            path_permission = False

        self.sqlstdout.write(sqlsentence % (provider_name,
                                            read_permission,
                                            write_permission,
                                            authority,
                                            multiprocess,
                                            grant_uri_permission,
                                            uri_permission_patterns,
                                            path_permission))


    def insert_with_intent(self, component, intent_filter, tableName):
        insert_sentence = "insert into " + tableName + " values('%s','%s','%s','%s');"
        insert_action = ''
        insert_category = ''
        insert_data = ''
        if len(intent_filter.actions) > 0:
            for action in intent_filter.actions:
                insert_action = action
                if self.check_action(action):
                    if len(intent_filter.categories) > 0:
                        for category in intent_filter.categories:
                            insert_category = category
                            if self.check_category(category):
                                if len(intent_filter.datas) > 0:
                                    for data in intent_filter.datas:
                                        insert_data = data
                                        self.sqlstdout.write(
                                            insert_sentence % (component.name, insert_action, insert_category, insert_data))
                                else:
                                    self.sqlstdout.write(
                                        insert_sentence % (component.name, insert_action, insert_category, insert_data))
                    else:
                        self.sqlstdout.write(
                            insert_sentence % (component.name, insert_action, insert_category, insert_data))

    def scan_webview(self):
        web_activities = self.findBrowserableActivity(self.attackable_package_name)
        for web_activity in web_activities:
            intent_filters = self.find_intent_filters(web_activity, 'activity')
            if len(intent_filters)>0:
                '''
                     建立intent_set 避免重复启用某一个activity
                '''
                intent_set = []
                for intent_filter in intent_filters:
                    # self.startWithIntent(web_activity, intent_filter)

                    intent = self.new("android.content.Intent")
                    comp = (self.attackable_package_name, web_activity.name)
                    com = self.new("android.content.ComponentName", *comp)
                    if len(intent_filter.actions) > 0:
                        for action in intent_filter.actions:
                            if action != '' and action != "android.intent.action.MAIN" and (action in android.Intent.actions):
                                intent.setAction(action)
                                intent.setComponent(com)
                                if len(intent_filter.categories) > 0:
                                    for category in intent_filter.categories:
                                        if category == "android.intent.category.BROWSABLE":
                                            intent.addCategory(category)

                                            if len(intent_filter.datas) > 0:
                                                for data in intent_filter.datas:
                                                    if "http" == data.scheme:
                                                        if not [web_activity.name, action, category] in intent_set:
                                                            intent_set.append([web_activity.name, action, category])

                                                            # data = "http://uxss.sinaapp.com/index.php"
                                                            data = "file:///sdcard/data-app/attack.html"
                                                            # data = "10.199.157.32:82//attack.html"
                                                            uri = self.klass("android.net.Uri")
                                                            intent.setData(uri.parse(data))
                                                            intent.setFlags(0x10000000)
                                                            context = self.getContext()


                                                            print "name:", web_activity.name
                                                            print "action: ", action
                                                            print "data:" , data
                                                            print "category:",category
                                                            try:
                                                                 context.startActivity(intent)
                                                            except:
                                                                print "err"
                                                            # context.onStop()
                                                            # context.stopActivity(intent)



    def startWithIntent(self, compment, intent_filter):
        try:
            self.stdout.write("trying start %s with intent..." % (compment.name))
            intent = self.new("android.content.Intent")
            comp = (self.attackable_package_name, compment.name)
            com = self.new("android.content.ComponentName", *comp)
            if len(intent_filter.actions) > 0:
                for action in intent_filter.actions:
                    if self.check_action(action):
                        intent.setAction(action)
                        intent.setComponent(com)
                        if len(intent_filter.categories) > 0:
                            for category in intent_filter.categories:
                                if self.check_category(category):
                                    intent.addCategory(category)
                                    # if len(intent_filter.datas) > 0:
                                        # for data in intent_filter.datas:
                                        #     data = "http://uxss.sinaapp.com/index.php"
                                        #     uri = self.klass("android.net.Uri")
                                        #     intent.setData(uri.parse(data))
                                        #     intent.setFlags(0x10000000)
                                        #     self.stdout.write('''
                                        #     action:....%s
                                        #     category:...%s
                                        #     data:...%s
                                        #      '''
                                        #      % (action, category, data))
                                        #     context = self.getContext()
                                        #     result = context.startActivity(intent)
                                        #     self.stdout.write("start successfully")
                                    intent.setFlags(0x10000000)
                                    self.getContext().startActivity(intent)
        except Exception:
            self.stdout.write("start %s with action :%s error" % (compment.name, action.name))


    def startWithNull(self, compment):
        try:
            self.stdout.write("trying start %s directly." % (compment.name))
            comp = (self.attackable_package_name, compment.name)
            intent = self.new("android.content.Intent")
            com = self.new("android.content.ComponentName", *comp)
            intent.setComponent(com)
            intent.setFlags(0x10000000)
            self.getContext().startActivity(intent)

        except Exception:
            self.stdout.write("trying start %s....ERROR" % (compment.name))
            """
            check action and category
            """
    def check_action(self, action):
        if (action in android.Intent.actions) and (action != None) and (action != "android.intent.action.MAIN"):
            return True
    def check_category(self, category):
        if category in android.Intent.categories:
            return True


class Info(Module, common.Filters, common.PackageManager, common.IntentFilter):
    name = "Get information about installed packages"
    description = "List all installed packages on the device with optional filters. Specify optional keywords to search for in the package information, or granted permissions."
    examples = """Finding all packages with the keyword "browser" in their name:

    dz> run app.package.info -f browser

    Package: com.android.browser
      Process name: com.android.browser
      Version: 4.1.1
      Data Directory: /data/data/com.android.browser
      APK path: /system/app/Browser.apk
      UID: 10014
      GID: [3003, 1015, 1028]
      Shared libraries: null
      Permissions:
      - android.permission.ACCESS_COARSE_LOCATION
      - android.permission.ACCESS_DOWNLOAD_MANAGER
      - android.permission.ACCESS_FINE_LOCATION
      ...

Finding all packages with the "INSTALL_PACKAGES" permission:

    dz> run app.package.info -p INSTALL_PACKAGES

    Package: com.android.packageinstaller
      Process Name: com.android.packageinstaller
      Version: 4.1.1-403059
      Data Directory: /data/data/com.android.packageinstaller
      APK Path: /system/app/PackageInstaller.apk
      UID: 10003
      GID: [1028]
      Shared Libraries: null
      Shared User ID: null
      Permissions:
      - android.permission.INSTALL_PACKAGES
      - android.permission.DELETE_PACKAGES
      - android.permission.CLEAR_APP_CACHE
      - android.permission.READ_PHONE_STATE
      - android.permission.CLEAR_APP_USER_DATA
      - android.permission.READ_EXTERNAL_STORAGE"""
    author = "MWR InfoSecurity (@mwrlabs)"
    date = "2012-11-06"
    license = "BSD (3 clause)"
    path = ["app", "package"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]

    def add_arguments(self, parser):
        parser.add_argument("-a", "--package", default=None, help="the identifier of the package to inspect")
        parser.add_argument("-d", "--defines-permission", default=None,
                            help="filter by the permissions a package defines")
        parser.add_argument("-f", "--filter", default=None, help="keyword filter conditions")
        parser.add_argument("-g", "--gid", default=None, help="filter packages by GID")
        parser.add_argument("-p", "--permission", default=None, help="permission filter conditions")
        parser.add_argument("-u", "--uid", default=None, help="filter packages by UID")
        parser.add_argument("-i", "--show-intent-filters", action="store_true", default=False,
                            help="show intent filters")

    def execute(self, arguments):
        if arguments.package == None:
            for package in self.packageManager().getPackages(
                                                    common.PackageManager.GET_PERMISSIONS | common.PackageManager.GET_CONFIGURATIONS | common.PackageManager.GET_GIDS | common.PackageManager.GET_SHARED_LIBRARY_FILES | common.PackageManager.GET_ACTIVITIES):
                self.__get_package(arguments, package)
        else:
            package = self.packageManager().getPackageInfo(arguments.package,
                                                           common.PackageManager.GET_PERMISSIONS | common.PackageManager.GET_CONFIGURATIONS | common.PackageManager.GET_GIDS | common.PackageManager.GET_SHARED_LIBRARY_FILES | common.PackageManager.GET_ACTIVITIES)
            self.__get_package(arguments, package)

    def get_completion_suggestions(self, action, text, **kwargs):
        if action.dest == "permission":
            return android.permissions

    def __print_intent_filters(self, intent_filters):
        for intent_filter in intent_filters:
            if len(intent_filter.actions) > 0:
                self.stdout.write("    - Actions:\n")
                for action in intent_filter.actions:
                    self.stdout.write("      - %s\n" % action)
            if len(intent_filter.categories) > 0:
                self.stdout.write("    - Categories:\n")
                for category in intent_filter.categories:
                    self.stdout.write("      - %s\n" % category)
            if len(intent_filter.datas) > 0:
                self.stdout.write("    - Data:\n")
                for data in intent_filter.datas:
                    self.stdout.write("      - %s\n" % data)

    def __get_package(self, arguments, package):
        application = package.applicationInfo
        activities = package.activities
        services = package.services

        intent_matches = not (arguments.show_intent_filters and arguments.filter)

        if not intent_matches and arguments.filter is not None:
            if activities is not None:
                for activity in activities:
                    if not intent_matches:
                        for intent_filter in self.find_intent_filters(activity, 'activity'):
                            if len(intent_filter.actions) > 0:
                                for action in intent_filter.actions:
                                    if action is not None and action.upper().find(arguments.filter.upper()) >= 0:
                                        intent_matches = True
                                        break

                            if len(intent_filter.datas) > 0:
                                for data in intent_filter.datas:
                                    if data.scheme is not None and data.scheme is not False and data.scheme.upper().find(
                                            arguments.filter.upper()) >= 0:
                                        intent_matches = True
                                        break

                            if len(intent_filter.categories) > 0:
                                for category in intent_filter.categories:
                                    if category != None and category.upper().find(arguments.filter.upper()) >= 0:
                                        intent_matches = True
                                        break
                    else:
                        break

            if services != None:
                for service in services:
                    if not intent_matches:
                        for intent_filter in self.find_intent_filters(service, 'service'):
                            if len(intent_filter.actions) > 0:
                                for action in intent_filter.actions:
                                    if action != None and action.upper().find(arguments.filter.upper()) >= 0:
                                        intent_matches = True
                                        break

                            if len(intent_filter.uris) > 0:
                                for data in intent_filter.datas:
                                    if data.scheme != None and data.scheme != False and data.scheme.upper().find(
                                            arguments.filter.upper()) >= 0:
                                        intent_matches = True
                                        break

                            if len(intent_filter.categories) > 0:
                                for category in intent_filter.categories:
                                    if category != None and category.upper().find(arguments.filter.upper()) >= 0:
                                        intent_matches = True
                                        break
                    else:
                        break

        if (arguments.defines_permission == None or package.permissions != None and True in map(
                lambda p: p.name.upper().find(arguments.defines_permission.upper()) >= 0, package.permissions)) and (
                            arguments.filter == None or package.packageName.upper().find(
                            arguments.filter.upper()) >= 0 or self.packageManager().getApplicationLabel(
                        package.packageName).upper().find(arguments.filter.upper()) >= 0) and (
                        arguments.gid == None or package.gids != None and True in map(lambda g: g == int(arguments.gid),
                                                                                      package.gids)) and (
                        arguments.permission == None or package.requestedPermissions != None and True in map(
                        lambda p: p.upper().find(arguments.permission.upper()) >= 0,
                        package.requestedPermissions)) and (
                        arguments.uid == None or arguments.uid == str(package.applicationInfo.uid)) and intent_matches:
            self.stdout.write("Package: %s\n" % application.packageName)
            self.stdout.write(
                "  Application Label: %s\n" % self.packageManager().getApplicationLabel(application.packageName))
            self.stdout.write("  Process Name: %s\n" % application.processName)
            self.stdout.write("  Version: %s\n" % package.versionName)
            self.stdout.write("  Data Directory: %s\n" % application.dataDir)
            self.stdout.write("  APK Path: %s\n" % application.publicSourceDir)
            self.stdout.write("  UID: %s\n" % application.uid)
            if package.gids != None:
                self.stdout.write("  GID: %s\n" % package.gids)
            else:
                self.stdout.write("  GID: None\n")
            self.stdout.write("  Shared Libraries: %s\n" % application.sharedLibraryFiles)
            self.stdout.write("  Shared User ID: %s\n" % package.sharedUserId)
            self.stdout.write("  Uses Permissions:\n")
            if package.requestedPermissions != None:
                for permission in package.requestedPermissions:
                    self.stdout.write("  - %s\n" % permission)
            else:
                self.stdout.write("  - None\n")
            self.stdout.write("  Defines Permissions:\n")
            if package.permissions != None:
                for permission in package.permissions:
                    self.stdout.write("  - %s\n" % permission.name)
            else:
                self.stdout.write("  - None\n")
            if arguments.show_intent_filters:
                ifcount = 0
                self.stdout.write("  Intent Filters:\n")

                if activities != None:
                    for activity in activities:
                        intent_filters = self.find_intent_filters(activity, 'activity')
                        if len(intent_filters) > 0:
                            ifcount += len(intent_filters)

                            self.stdout.write("  - %s\n" % activity.name)
                            self.__print_intent_filters(intent_filters)

                if services != None:
                    for service in services:
                        intent_filters = self.find_intent_filters(service, 'service')
                        if len(intent_filters) > 0:
                            ifcount += len(intent_filters)

                            self.stdout.write("  - %s\n" % service.name)
                            self.__print_intent_filters(intent_filters)

                if ifcount == 0:
                    self.stdout.write("  - None")
            self.stdout.write("\n")


class LaunchIntent(Module, common.PackageManager):
    name = "Get launch intent of package"
    description = "Get the launch intent of an installed package."
    examples = """Finding the launch intent of the Android browser package:

    dz> run app.package.launchintent com.android.browser

    Intent: 
      Action: android.intent.action.MAIN
      Component: {com.android.browser/com.android.browser.BrowserActivity}
      Data: null
      Categories: 
        android.intent.category.LAUNCHER
      Flags: [ACTIVITY_NEW_TASK]
      Mime Type: null
      Extras: null"""
    author = "MWR InfoSecurity (@mwrlabs)"
    date = "2013-03-06"
    license = "BSD (3 clause)"
    path = ["app", "package"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]

    def add_arguments(self, parser):
        parser.add_argument("package", help="the identifier of the package to inspect")
        parser.add_argument("-r", "--raw", action="store_true", default=False,
                            help="display the raw output of the intent (as if you were calling intent.toString())")

    def execute(self, arguments):
        intent = self.packageManager().getLaunchIntentForPackage(arguments.package)

        if intent != None:
            if not arguments.raw:
                self.processIntent(intent)
            else:
                self.stdout.write("%s\n\n" % str(intent.toString()))
        else:
            self.stdout.write("No Launch Intent found.\n\n")

    def processIntent(self, intent):

        self.stdout.write("Launch Intent:\n")
        self.stdout.write("  Action: %s\n" % intent.getAction())
        self.stdout.write("  Component: %s\n" % intent.getComponent().toShortString())
        self.stdout.write("  Data: %s\n" % intent.getDataString())
        if intent.getCategories() == None:
            self.stdout.write("  Categories: null\n")
        else:
            self.stdout.write("  Categories: \n")
            for category in intent.getCategories().toArray():
                self.stdout.write("     - %s\n" % str(category.toString()))

        self.stdout.write("  Flags: %s\n" % self.processFlags(intent.getFlags()))
        self.stdout.write("  Mime Type: %s\n" % intent.getType())

        extras = intent.getExtras()
        if extras != None:
            if not extras.isEmpty():
                self.stdout.write("  Extras: \n")
                for extra in extras.keySet():
                    self.stdout.write("    - %s\n" % extras.get(extra))
        else:
            self.stdout.write("  Extras: null\n")

    def processFlags(self, flags):

        out = ""
        # flags are a bit mask
        for key in android.Intent.flags.keys():
            for i in range(0, 8):
                flag = flags & (0x0000000F << i * 4)
                if android.Intent.flags.get(key) == flag:
                    out = out + "%s, " % key
        if out is not "":
            return "[%s]" % out[:-2]
        else:
            return "null"


class List(Module, common.PackageManager):
    name = "List Packages"
    description = "List all installed packages on the device. Specify optional keywords to search for in the package name."
    examples = """Finding all packages with the keyword "browser" in their name:

    dz> run app.package.list -f browser

    com.android.browser"""
    author = "MWR InfoSecurity (@mwrlabs)"
    date = "2012-11-06"
    license = "BSD (3 clause)"
    path = ["app", "package"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]

    def add_arguments(self, parser):
        parser.add_argument("-d", "--defines-permission", default=None,
                            help="filter by the permissions a package defines")
        parser.add_argument("-f", "--filter", default=None, help="keyword filter conditions")
        parser.add_argument("-g", "--gid", default=None, help="filter packages by GID")
        parser.add_argument("-p", "--permission", default=None, help="permission filter conditions")
        parser.add_argument("-u", "--uid", default=None, help="filter packages by UID")
        parser.add_argument("-n", "--no_app_name", action="store_true", default=False, help="do not print the app name")

    def execute(self, arguments):
        packages = self.packageManager().getPackages(
            common.PackageManager.GET_PERMISSIONS | common.PackageManager.GET_CONFIGURATIONS | common.PackageManager.GET_GIDS | common.PackageManager.GET_SHARED_LIBRARY_FILES)
        for package in packages:
            self.__get_package(arguments, package)

    def __get_package(self, arguments, package):
        application = package.applicationInfo

        if (arguments.defines_permission == None or package.permissions != None and True in map(
                lambda p: p.name.upper().find(arguments.defines_permission.upper()) >= 0, package.permissions)) and (
                            arguments.filter == None or package.packageName.upper().find(
                            arguments.filter.upper()) >= 0 or self.packageManager().getApplicationLabel(
                        application.packageName).upper().find(arguments.filter.upper()) >= 0) and (
                        arguments.gid == None or package.gids != None and True in map(lambda g: g == int(arguments.gid),
                                                                                      package.gids)) and (
                        arguments.permission == None or package.requestedPermissions != None and True in map(
                        lambda p: p.upper().find(arguments.permission.upper()) >= 0,
                        package.requestedPermissions)) and (
                        arguments.uid == None or arguments.uid == str(package.applicationInfo.uid)):
            if arguments.no_app_name:
                self.stdout.write("%s\n" % application.packageName)
            else:
                self.stdout.write("%s (%s)\n" % (
                    application.packageName, self.packageManager().getApplicationLabel(application.packageName)))


class Manifest(Module, common.Assets):
    name = "Get AndroidManifest.xml of package"
    description = "Retrieves AndroidManifest.xml from an installed package."
    examples = """Getting the manifest for drozer

    dz> run app.package.manifest com.mwr.dz

    <manifest versionCode="2" versionName="1.1" package="com.mwr.dz">
      <uses-sdk minSdkVersion="8" targetSdkVersion="4">
      </uses-sdk>
      <uses-permission name="android.permission.INTERNET">
      </uses-permission>

      ...
    </manifest>"""
    author = "MWR InfoSecurity (@mwrlabs)"
    date = "2012-11-06"
    license = "BSD (3 clause)"
    path = ["app", "package"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]

    def add_arguments(self, parser):
        parser.add_argument("package", help="the identifier of the package")

    def execute(self, arguments):
        if arguments.package == None or arguments.package == "":
            self.stderr.write("No package provided.\n")
        else:
            AndroidManifest = self.getAndroidManifest(arguments.package)
            self.__write_manifest(AndroidManifest)

    def __write_manifest(self, manifest):
        lines = manifest.split("\n")
        level = 0

        for line in lines:
            # self.txmlstdout.write(line)
            if line.startswith("</"):
                level -= 1

            if line.startswith("<") and not line.startswith("</"):
                pattern = re.compile("(.*)<([^>]+)>(.*)")
                match = pattern.match(line)

                contents = match.group(2).split(" ", 1)

                self.txmlstdout.write("%s%s<[color green]%s[/color]" % ("  " * level, match.group(1), contents[0]))

                if len(contents) > 1:
                    self.txmlstdout.write(("\n%s%s" % ("  " * level, " " * (len(contents[0]) + 1))).join(
                        map(lambda m: " [color purple]%s[/color]=[color red]\"%s\"[/color]" % m,
                            re.compile("([^=]+)=\"([^\"]+)\"\s*").findall(contents[1]))))

                self.txmlstdout.write(">\n")
            else:
                self.txmlstdout.write("%s%s\n" % ("  " * level, line))

            if line.startswith("<") and not "</" in line:
                level += 1


class Native(Module, common.ClassLoader, common.PackageManager):
    name = "Find Native libraries embedded in the application."
    description = "Find Native libraries embedded in the application."
    examples = ""
    author = "MWR InfoSecurity (@mwrlabs)"
    date = "2013-03-23"
    license = "BSD (3 clause)"
    path = ["app", "package"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]

    def add_arguments(self, parser):
        parser.add_argument("package", help="the identifier of the package")

    def execute(self, arguments):
        Native = self.loadClass("common/Native.apk", "Native")

        package = self.packageManager().getPackageInfo(arguments.package, common.PackageManager.GET_PROVIDERS)
        libraries = Native.list(package.applicationInfo)

        if len(libraries) > 0:
            self.stdout.write("Package: %s\n" % package.packageName)
            self.stdout.write("  Native Libraries:\n")

            for library in libraries:
                self.stdout.write("   - %s\n" % library)
            self.stdout.write("\n")
        else:
            self.stdout.write("Package: %s\n" % package.packageName)
            self.stdout.write("  No Native Libraries.\n")
            self.stdout.write("\n")


class SharedUID(Module, common.PackageManager):
    name = "Look for packages with shared UIDs"
    description = "Finds packages that have shared UIDs and gives their accumulated permissions."
    examples = """Finding packages that share the UID 10011

    dz> run app.package.shareduid -u 10011

    UID: 10011 (com.motorola.blur.uid.provider_authenticator:10011)
    Package Name: com.motorola.blur.provider.photobucket
    Package Name: com.motorola.blur.provider.picasa
    Package Name: com.motorola.blur.provider.yahoo
    Package Name: com.motorola.blur.provider.twitter
    Package Name: com.motorola.blur.provider.fixedemail
    Package Name: com.motorola.blur.provider.motorola.app
    Package Name: com.motorola.blur.provider.orkut
    Package Name: com.motorola.blur.provider.email
    Package Name: com.motorola.blur.provider.facebook
    Package Name: com.motorola.blur.provider.lastfm
    Package Name: com.motorola.blur.provider.linkedin
    Package Name: com.motorola.blur.provider.youtube
    Package Name: com.motorola.blur.provider.skyrock
    Package Name: com.motorola.blur.provider.activesync
    Package Name: com.motorola.blur.provider.flickr
    Accumulated permissions: com.motorola.blur.setupprovider.Permissions.ACCESS_ACCOUNTS; ..."""
    author = "MWR InfoSecurity (@mwrlabs)"
    date = "2012-11-06"
    license = "BSD (3 clause)"
    path = ["app", "package"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]

    def add_arguments(self, parser):
        parser.add_argument("-u", "--uid", default=None, help="specify uid")

    def execute(self, arguments):
        uids = set([])

        if arguments.uid == None:
            for package in self.packageManager().getPackages(common.PackageManager.GET_PERMISSIONS):
                uids.add(int(package.applicationInfo.uid))
        else:
            uids.add(int(arguments.uid))

        for uid in uids:
            self.stdout.write("UID: %d (%s)\n" % (uid, self.packageManager().getNameForUid(uid)))

            packages = self.packageManager().getPackagesForUid(uid)

            if packages != None:
                permissions = set([])

                for packageName in packages:
                    package = self.packageManager().getPackageInfo(packageName, common.PackageManager.GET_PERMISSIONS)

                    self.stdout.write("  Package: %s\n" % packageName)

                    if package.requestedPermissions != None:
                        for permission in package.requestedPermissions:
                            permissions.add(permission)

                self.stdout.write("  Permissions: %s\n" % ", ".join(map(lambda p: str(p), permissions)))
                self.stdout.write("\n")
            else:
                self.stdout.write("No such UID.\n")
