#!/usr/bin/env python3
"""Generate the three-target Xcode project without third-party project generators."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / 'apps/ios'
objects = {}

def ident(name):
    return hashlib.sha256(name.encode()).hexdigest()[:24].upper()

def add(key_name, isa, **fields):
    key = ident(key_name)
    objects[key] = dict(isa=isa, **fields)
    return key

def reference(path, kind):
    return add('file:' + path, 'PBXFileReference', lastKnownFileType=kind, path=path, sourceTree='<group>')

shared = reference('Shared/Profile.swift', 'sourcecode.swift')
header = reference('Shared/RTrustCore.h', 'sourcecode.c.h')
app = reference('App/RTrustApp.swift', 'sourcecode.swift')
extension = reference('PacketTunnel/PacketTunnelProvider.swift', 'sourcecode.swift')
app_product = add('app-product', 'PBXFileReference', explicitFileType='wrapper.application', path='R-TrustTunnel.app', sourceTree='BUILT_PRODUCTS_DIR')
ext_product = add('ext-product', 'PBXFileReference', explicitFileType='wrapper.app-extension', path='PacketTunnel.appex', sourceTree='BUILT_PRODUCTS_DIR')
widget_product = add('widget-product', 'PBXFileReference', explicitFileType='wrapper.app-extension', path='VPNWidget.appex', sourceTree='BUILT_PRODUCTS_DIR')
products = add('products', 'PBXGroup', children=[app_product, ext_product, widget_product], name='Products', sourceTree='<group>')
resources = [reference(f'{folder}/{name}', kind) for folder in ('App', 'PacketTunnel', 'Widget') for name, kind in [('Info.plist', 'text.plist.xml'), ('App.entitlements', 'text.plist.entitlements')]]
extra_paths = ['Shared/VPNController.swift','Shared/WidgetState.swift','App/VPNModel.swift','App/SettingsView.swift','App/PortalClient.swift','App/QRImport.swift','Widget/VPNWidget.swift']
extra = {path: reference(path, 'sourcecode.swift') for path in extra_paths}
localizations = [add('locale-'+lang, 'PBXFileReference', lastKnownFileType='text.plist.strings', name=lang, path='Resources/'+lang+'.lproj/Localizable.strings', sourceTree='<group>') for lang in ('en','ru')]
localized = add('localized','PBXVariantGroup',children=localizations,name='Localizable.strings',sourceTree='<group>')
main = add('main', 'PBXGroup', children=[shared,header,app,extension,*extra.values(),*resources,localized,products], sourceTree='<group>')

def configs(name, settings):
    entries = []
    for configuration in ('Debug', 'Release'):
        entries.append(add(f'{name}-{configuration}', 'XCBuildConfiguration', name=configuration, buildSettings=settings | {'SWIFT_OPTIMIZATION_LEVEL': '-Onone' if configuration == 'Debug' else '-O', 'ENABLE_TESTABILITY': 'YES' if configuration == 'Debug' else 'NO'}))
    return add(name+'-config-list', 'XCConfigurationList', buildConfigurations=entries, defaultConfigurationIsVisible=0, defaultConfigurationName='Release')

common = {'IPHONEOS_DEPLOYMENT_TARGET':'16.0', 'SDKROOT':'iphoneos', 'SUPPORTED_PLATFORMS':'iphoneos iphonesimulator', 'TARGETED_DEVICE_FAMILY':'1', 'SWIFT_VERSION':'5.0', 'CLANG_ENABLE_MODULES':'YES', 'CODE_SIGN_STYLE':'Automatic', 'RTRUST_BUNDLE_ID':'org.rtrusttunnel.ios', 'ENABLE_USER_SCRIPT_SANDBOXING':'NO', 'SWIFT_OBJC_BRIDGING_HEADER':'Shared/RTrustCore.h', 'LIBRARY_SEARCH_PATHS':['$(inherited)', '$(SRCROOT)/../../target/$(RTRUST_RUST_TARGET)/release'], 'OTHER_LDFLAGS':['$(inherited)', '-lrtrust_ios', '-framework', 'Security', '-framework', 'SystemConfiguration', '-framework', 'NetworkExtension', '-liconv', '-lresolv'], 'RTRUST_RUST_TARGET[sdk=iphoneos*]':'aarch64-apple-ios', 'RTRUST_RUST_TARGET[sdk=iphonesimulator*]':'aarch64-apple-ios-sim', 'ARCHS':'arm64', 'ENABLE_BITCODE':'NO'}
project_configs = configs('project',common)

for name, source, product, folder in [('PacketTunnel',extension,ext_product,'PacketTunnel'), ('RTrustTunnel',app,app_product,'App'), ('VPNWidget',extra['Widget/VPNWidget.swift'],widget_product,'Widget')]:
    sources = [source, extra['Shared/WidgetState.swift']]
    if folder != 'Widget': sources.append(shared)
    if folder in ('App','Widget'): sources.append(extra['Shared/VPNController.swift'])
    if folder == 'App': sources += [extra[p] for p in extra_paths if p.startswith('App/')]
    build_files=[add(name+'-'+str(index),'PBXBuildFile',fileRef=f) for index,f in enumerate(sources)]
    phases=[add(name+'-sources','PBXSourcesBuildPhase',buildActionMask=2147483647, files=build_files, runOnlyForDeploymentPostprocessing=0)]
    phases += [add(name+'-frameworks','PBXFrameworksBuildPhase',buildActionMask=2147483647,files=[],runOnlyForDeploymentPostprocessing=0)]
    if folder in ('App','Widget'):
        localized_build = add(name+'-localization','PBXBuildFile',fileRef=localized)
        phases.append(add(name+'-resources','PBXResourcesBuildPhase',buildActionMask=2147483647,files=[localized_build],runOnlyForDeploymentPostprocessing=0))
    dependencies=[]
    if folder == 'App':
        embeds=[]
        for target, product_ref in [('PacketTunnel',ext_product),('VPNWidget',widget_product)]:
            embeds.append(add('embed-'+target+'-file','PBXBuildFile',fileRef=product_ref,settings={'ATTRIBUTES':['RemoveHeadersOnCopy']}))
            proxy=add(target+'-proxy','PBXContainerItemProxy',containerPortal=ident('project'),proxyType=1,remoteGlobalIDString=ident(target+'-target'),remoteInfo=target)
            dependencies.append(add(target+'-dependency','PBXTargetDependency',target=ident(target+'-target'),targetProxy=proxy))
        phases += [add('embed-extension','PBXCopyFilesBuildPhase',buildActionMask=2147483647,dstPath='',dstSubfolderSpec=13,files=embeds,name='Embed App Extensions',runOnlyForDeploymentPostprocessing=0)]
    target_settings={'PRODUCT_NAME':'R-TrustTunnel' if folder=='App' else name,'PRODUCT_MODULE_NAME':name, 'PRODUCT_BUNDLE_IDENTIFIER':'$(RTRUST_BUNDLE_ID)' + ('.'+name if folder!='App' else ''),'INFOPLIST_FILE':folder+'/Info.plist','CODE_SIGN_ENTITLEMENTS':folder+'/App.entitlements','LD_RUNPATH_SEARCH_PATHS':['$(inherited)','@executable_path/Frameworks','@executable_path/../../Frameworks'],'SKIP_INSTALL':'YES' if folder!='App' else 'NO'}
    if folder!='App': target_settings['APPLICATION_EXTENSION_API_ONLY']='YES'
    if folder=='Widget':
        target_settings['SWIFT_OBJC_BRIDGING_HEADER']=''
        target_settings['OTHER_LDFLAGS']=['-framework','NetworkExtension','-framework','WidgetKit']
    add(name+'-target','PBXNativeTarget',buildConfigurationList=configs(name,target_settings),buildPhases=phases,buildRules=[],dependencies=dependencies,name=name,productName=name,productReference=product,productType='com.apple.product-type.application' if folder=='App' else 'com.apple.product-type.app-extension')
test_source = reference('Tests/ParityTests.swift', 'sourcecode.swift')
objects[main]['children'].append(test_source)
test_product = add('tests-product','PBXFileReference',explicitFileType='wrapper.cfbundle',path='ParityTests.xctest',sourceTree='BUILT_PRODUCTS_DIR')
objects[products]['children'].append(test_product)
test_file = add('tests-file','PBXBuildFile',fileRef=test_source)
test_phase = add('tests-sources','PBXSourcesBuildPhase',buildActionMask=2147483647,files=[test_file],runOnlyForDeploymentPostprocessing=0)
test_proxy = add('tests-app-proxy','PBXContainerItemProxy',containerPortal=ident('project'),proxyType=1,remoteGlobalIDString=ident('RTrustTunnel-target'),remoteInfo='RTrustTunnel')
test_dependency = add('tests-app-dependency','PBXTargetDependency',target=ident('RTrustTunnel-target'),targetProxy=test_proxy)
add('ParityTests-target','PBXNativeTarget',buildConfigurationList=configs('tests',{'PRODUCT_NAME':'ParityTests','PRODUCT_BUNDLE_IDENTIFIER':'$(RTRUST_BUNDLE_ID).Tests','GENERATE_INFOPLIST_FILE':'YES','TEST_HOST':'$(BUILT_PRODUCTS_DIR)/R-TrustTunnel.app/R-TrustTunnel','BUNDLE_LOADER':'$(TEST_HOST)','SWIFT_OBJC_BRIDGING_HEADER':'','OTHER_LDFLAGS':[],'LD_RUNPATH_SEARCH_PATHS':['$(inherited)','@executable_path/Frameworks','@loader_path/Frameworks']}),buildPhases=[test_phase],buildRules=[],dependencies=[test_dependency],name='ParityTests',productName='ParityTests',productReference=test_product,productType='com.apple.product-type.bundle.unit-test')
add('project','PBXProject',attributes={'LastUpgradeCheck':'1600','BuildIndependentTargetsInParallel':'YES'},buildConfigurationList=project_configs,compatibilityVersion='Xcode 14.0',developmentRegion='en',hasScannedForEncodings=0,knownRegions=['en','ru','Base'],mainGroup=main,productRefGroup=products,projectDirPath='',projectRoot='',targets=[ident('RTrustTunnel-target'),ident('PacketTunnel-target'),ident('VPNWidget-target'),ident('ParityTests-target')])

def encode(value, depth=0):
    if isinstance(value,dict): return '{\n' + '\n'.join('\t'*(depth+1)+json.dumps(k)+' = '+encode(v,depth+1)+';' for k,v in value.items())+'\n'+'\t'*depth+'}'
    if isinstance(value,list): return '('+', '.join(encode(v,depth) for v in value)+')'
    return json.dumps(value)

project=ROOT/'RTrustTunnel.xcodeproj'
project.mkdir(exist_ok=True)
(project/'project.pbxproj').write_text('// !$*UTF8*$!\n'+encode({'archiveVersion':1,'classes':{},'objectVersion':56,'objects':objects,'rootObject':ident('project')})+'\n')
schemes=project/'xcshareddata/xcschemes'
schemes.mkdir(parents=True,exist_ok=True)
(schemes/'RTrustTunnel.xcscheme').write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1600" version="1.3">
<BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{ident('RTrustTunnel-target')}" BuildableName="R-TrustTunnel.app" BlueprintName="RTrustTunnel" ReferencedContainer="container:RTrustTunnel.xcodeproj"/></BuildActionEntry></BuildActionEntries></BuildAction>
<TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES"><Testables><TestableReference skipped="NO"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{ident('ParityTests-target')}" BuildableName="ParityTests.xctest" BlueprintName="ParityTests" ReferencedContainer="container:RTrustTunnel.xcodeproj"/></TestableReference></Testables></TestAction>
<LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" allowLocationSimulation="YES"><BuildableProductRunnable runnableDebuggingMode="0"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{ident('RTrustTunnel-target')}" BuildableName="R-TrustTunnel.app" BlueprintName="RTrustTunnel" ReferencedContainer="container:RTrustTunnel.xcodeproj"/></BuildableProductRunnable></LaunchAction>
<ProfileAction buildConfiguration="Release" shouldUseLaunchSchemeArgsEnv="YES" savedToolIdentifier="" useCustomWorkingDirectory="NO" debugDocumentVersioning="YES"/>
<AnalyzeAction buildConfiguration="Debug"/><ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
''')
print(project)
