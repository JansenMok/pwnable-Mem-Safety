# CS161 project 1 submission script
# Last updated: January 30, 2023
#
# We recommend running this script in an empty directory to avoid affecting other files.
#
# This is a quick script to copy your Project 1 solutions out of the VM
# for submission. Directly copy-pasting out of the VM is not
# recommended because it might insert weird characters.
#
# If you want to submit only partially, simply ignore the
# password prompt for any users you want to skip with ctrl+C.
#
# To create the submission manually, create the following
# directory structure: 
#
# customizer/.customization
# remus/egg
# spica/egg
# polaris/interact
# vega/arg
# vega/egg
# deneb/interact
# antares/egg
# antares/arg
# rigel/egg
#
# and zip these folders. (Do not zip a single folder that
# contains all the user folders within it.)

import sys
import os
from zipfile import ZipFile

# create temp folders for each user
try:
    for i in ['customizer', 'remus', 'spica', 'polaris', 'vega', 'deneb', 'antares', 'rigel']:
        os.mkdir(i)
except OSError:
    print('CONFLICTING FILE(S) DETECTED!')
    print('Move this script into an empty directory, and try again.')
    sys.exit()

# copy student files out of the VM
#print('YOU MUST INCLUDE THE CUSTOMIZER FILE TO PASS THE AUTOGRADER!')
#print('(type the password \'customizer\'.)')
#print('The password is \'customizer\'.')
#os.system('scp -P 16122 customizer@127.0.0.1:~/.customization customizer')
#print('The password is \'ilearned\'.')
#os.system('scp -P 16122 remus@127.0.0.1:~/egg remus')
#print('The password is \'alanguage\'.')
#os.system('scp -P 16122 spica@127.0.0.1:~/egg spica')
#print('The password is \'tolearn\'.')
#os.system('scp -P 16122 polaris@127.0.0.1:~/interact polaris')
#print('The password is \'whyishould\'.')
#os.system('scp -P 16122 vega@127.0.0.1:~/egg vega')
#print('The password is \'whyishould\'.')
#os.system('scp -P 16122 vega@127.0.0.1:~/arg vega')
#print('The password is \'neveruse\'.')
#os.system('scp -P 16122 deneb@127.0.0.1:~/interact deneb')
#print('The password is \'thatlanguage\'.')
#os.system('scp -P 16122 antares@127.0.0.1:~/egg antares')
#print('The password is \'thatlanguage\'.')
#os.system('scp -P 16122 antares@127.0.0.1:~/arg antares')
#print('The password is \'usegolanginstead\'.')
#os.system('scp -P 16122 rigel@127.0.0.1:~/interact rigel')
os.system('scp -P 16122 deneb@127.0.0.1:~/orbit.c deneb')
print('The password is \'thatlanguage\'.')

# zip up folders. this could be a one-line call to
# os.system, but since git bash has no zip command,
# we get to do this fun thing.
#files = ['customizer/.customization', 'remus/egg', 'spica/egg',
#         'polaris/interact', 'vega/egg', 'vega/arg', 'deneb/interact',
#         'antares/egg', 'antares/arg', 'rigel/interact']
files = ['deneb/orbit.c']
with ZipFile('submission.zip', 'w') as z:
    for i in files:
        if os.path.exists(i):
            z.write(i)

# remove the temp user folders
os.system('rm -rf customizer remus spica polaris vega deneb antares rigel')
print('Done! Upload submission.zip to Gradescope.')
