#!/usr/bin/env python3

import os
import sys
import subprocess
import re
import json
import glob
import sysconfig

here = re.split(r'/(?=[^/]*$)', sys.argv[0])
if len(here) > 1:
    os.chdir(here[0])

def newer(*files) :
    assert len(files) > 1
    rh = files[-1]
    if not os.path.exists(rh) :
        return True
    for lh in files[:-1] :
        if os.stat(lh).st_ctime > os.stat(rh).st_ctime :
            return True
    return False

if newer("../blst.h", "../libblst.a") :
    print("building libblst.a...") or sys.stdout.flush()
    subprocess.check_call(["../build.sh"], cwd="..")

if newer("../blst.swg", "../blst.h", "../blst.hpp", "blst_wrap.cpp") :
    print("swig-ing...") or sys.stdout.flush()
    subprocess.check_call(["swig", "-c++", "-python", "-O",
                                   "-o", "blst_wrap.cpp", "-outdir", ".",
                                   "../blst.swg"])

if newer("blst_wrap.cpp", "../libblst.a", "_blst.so") :
    print("compiling _blst.so...") or sys.stdout.flush()
    if sysconfig.get_config_var('MACHDEP') == 'darwin' :
        cmd = ["c++", "-bundle", "-undefined", "dynamic_lookup"]
    else :
        cmd = ["c++", "-shared", "-Wl,-Bsymbolic"]
    cmd.extend(["-o", "_blst.so", "-fPIC",
                "-I"+sysconfig.get_config_var('INCLUDEPY'), "-I..",
                "-O", "-Wall", "blst_wrap.cpp", "../libblst.a"])
    subprocess.check_call(cmd)

print("testing...")
########################################################################
import blst

msg = b"assertion"		# this what we're signing
DST = b"MY-DST"			# domain separation tag

SK = blst.SecretKey()
SK.keygen(b"*"*32)		# secret key

########################################################################
# generate public key and signature

pk_for_wire = blst.P1(SK).serialize()

				# optional vvvvvvvvvvv augmentation
sig_for_wire = blst.P2().hash_to(msg, DST, pk_for_wire) \
                        .sign_with(SK) \
                        .serialize()

########################################################################
# at this point 'pk_for_wire', 'sig_for_wire' and 'msg' are
# "sent over network," so now on "receiver" side

sig = blst.P2_Affine(sig_for_wire)
pk  = blst.P1_Affine(pk_for_wire)
if not pk.in_group() :		# vet the public key
    raise AssertionError("disaster")
ctx = blst.Pairing(True, DST)
ctx.aggregate(pk, sig, msg, pk_for_wire)
ctx.commit()
if not ctx.finalverify() :
    raise AssertionError("disaster")

########################################################################
# generate public key and signature

pk_for_wire = blst.P2(SK).serialize()

				# optional vvvvvvvvvvv augmentation
sig_for_wire = blst.P1().hash_to(msg, DST, pk_for_wire) \
                        .sign_with(SK) \
                        .serialize()

########################################################################
# at this point 'pk_for_wire', 'sig_for_wire' and 'msg' are
# "sent over network," so now on "receiver" side

sig = blst.P1_Affine(sig_for_wire)
pk  = blst.P2_Affine(pk_for_wire)
if not pk.in_group() :		# vet the public key
    raise AssertionError("disaster")
ctx = blst.Pairing(True, DST)
ctx.aggregate(pk, sig, msg, pk_for_wire)
ctx.commit()
if not ctx.finalverify() :
    raise AssertionError("disaster")

if sys.version_info.major < 3:
    print("OK")
    sys.exit(0)

########################################################################
# from https://github.com/supranational/blst/issues/5

pk_for_wire = bytes.fromhex("ab10fc693d038b73d67279127501a05f0072cbb7147c68650ef6ac4e0a413e5cabd1f35c8711e1f7d9d885bbc3b8eddc")
sig_for_wire = bytes.fromhex("a44158c08c8c584477770feec2afa24d5a0b0bab2800414cb9efbb37c40339b6318c9349dad8de27ae644376d71232580ff5102c7a8579a6d2627c6e40b0ced737a60c66c7ebd377c04bf5ac957bf05bc8b6b09fbd7bdd2a7fa1090b5a0760bb")
msg = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
DST = bytes.fromhex("424c535f5349475f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f504f505f")

sig = blst.P2_Affine(sig_for_wire)
pk  = blst.P1_Affine(pk_for_wire)
if not pk.in_group() :		# vet the public key
    raise AssertionError("disaster")
if sig.core_verify(pk, True, msg, DST) != blst.BLST_SUCCESS :
    raise AssertionError("disaster")

########################################################################
# test vectors from draft-irtf-cfrg-hash-to-curve

coord = re.compile(r'0x([0-9a-f]+)(?:\s*,\s*0x([0-9a-f]+))?', re.IGNORECASE)

def serialize_json_point(P):
    ret = b''
    x = coord.search(P['x'])
    if x.group(2):
        ret += bytes.fromhex(x.group(2))
    ret += bytes.fromhex(x.group(1))
    y = coord.search(P['y'])
    if y.group(2):
        ret += bytes.fromhex(y.group(2))
    ret += bytes.fromhex(y.group(1))
    return ret

for file in glob.glob("../vectors/hash_to_curve/*.json"):
    print(file)
    data = json.load(open(file))

    if data['curve'] == "BLS12-381 G1":
        point = blst.P1()
    else:
        point = blst.P2()

    DST = bytes(data['dst'], 'ascii')

    if data['randomOracle']:
        func = "point.hash_to(msg, DST).serialize()"
    else:
        func = "point.encode_to(msg, DST).serialize()"

    for vec in data['vectors']:
        msg = bytes(vec['msg'], 'ascii')
        if eval(func) != serialize_json_point(vec['P']):
            raise AssertionError(msg)

########################################################################
# test multi-scalar multiplication for self-consistency

points = []
scalars = []
total = 0
for _ in range(0, 42):
    p = os.urandom(8)
    s = int.from_bytes(os.urandom(8), "big")
    points.append(blst.G1().mult(p))
    scalars.append(s)
    total += s * int.from_bytes(p, "little")
a = blst.P1s.mult_pippenger(blst.P1s.to_affine(points), scalars)
if not a.is_equal(blst.G1().mult(total)):
    raise AssertionError("disaster")

points = []
scalars = []
total = 0
for _ in range(0, 42):
    p = os.urandom(8)
    s = int.from_bytes(os.urandom(8), "big")
    points.append(blst.G2().mult(p))
    scalars.append(s)
    total += s * int.from_bytes(p, "little")
a = blst.P2s.mult_pippenger(blst.P2s.to_affine(points), scalars)
if not a.is_equal(blst.G2().mult(total)):
    raise AssertionError("disaster")

########################################################################
# rudimentary blind signature PoC

# Signer's public key
PK = blst.P1(SK).to_affine()

# User wants to have |msg| signed, chooses random |r|,
r = blst.Scalar().from_bendian(os.urandom(32))
# blinds the H(|msg|) with |r| and sends it to the Signer.
sig_for_wire = blst.P2().hash_to(msg, DST).sign_with(r).serialize()

# Signer signs and sends the result back to the User.
sig_for_wire = blst.P2(sig_for_wire).sign_with(SK).serialize()

# User unblinds the result with 1/|r| to produce the actual |signature|,
signature = blst.P2(sig_for_wire).sign_with(r.inverse()).to_affine()
# and now it can be verified as following...
ctx = blst.Pairing(True, DST)
ctx.aggregate(PK, signature, msg)
ctx.commit()
if not ctx.finalverify():
    raise AssertionError("disaster")

print("OK")
