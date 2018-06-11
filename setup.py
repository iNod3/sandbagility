import setuptools

VERSION_MAJOR = 1
VERSION_MINOR = 1

VERSION = "{major:d}.{minor:d}".format(
    major = VERSION_MAJOR,
    minor = VERSION_MINOR,
)

def dummy_src():
    return []

setuptools.setup(
    provides=['Sandbagility'],
    packages = setuptools.find_packages(),
    name="Sandbagility",
    version=VERSION,
    description='Sandbagility is a framework that allow introspection of a Windows VM without /DEBUG enabled.',
    url='https://iNod3@bitbucket.org/iNod3/sandbagility.git',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: Microsoft :: Windows',
        'Topic :: Software Development :: Debuggers',
    ],
    
    requires=[],
    
    # PyFDP need to compile the client FDP dlls
    # but there are not Python module compliant so
    # the standard build_clib command will raise errors. That's
    # why we hook build_clib in order to launch the cmake build script.
    libraries=[(
        'Sandbagility', dict(
            package = 'Sandbagility',
            sources = dummy_src()
        ),
    )],

    # cmdclass=dict(
        # build_clib=PyFDPCustomBuildClib,
    # ),

    # Tell setuptools not to zip into an egg file
    # That's mandatory whenever there is a filepath involved
    # (in our case via the LoadLibrary)
    zip_safe=False,

    # We have two dlls to package with the python lib.
    include_package_data=True,
    package_data={
        "Sandbagility": ["bin/*.dll", "inc/*.h"],
    }
)