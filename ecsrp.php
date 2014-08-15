<?php

/*
	ECSRP
	Copyright (C) 2014  Steve "Sc00bz" Thomas (steve at tobtu dot com)

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

header('Content-type: text/plain');

require_once('hkdf.php');
require_once('curve25519.php');

/**
 * Converts a password into a scalar.
 *
 * @param string $password
 * @param string $salt
 * @param string $curve
 * @param string $hardness
 * @return GMP|null
 */
function getScalarFromPassword($password, $salt, $curve, $hardness = '09')
{
	if (is_string($hardness))
	{
		if (strlen($hardness) === 1)
		{
			$hardness = '0' . $hardness;
		}
		elseif (strlen($hardness) != 2)
		{
			return null;
		}
		$ch0 = ord($hardness[0]);
		$ch1 = ord($hardness[1]);
		if ($ch0 < 48 || $ch0 > 51 || $ch1 < 48 || $ch1 > 57 || ($ch0 == 51 && $ch1 > 49))
		{
			return null;
		}
	}
	elseif (is_int($hardness))
	{
		if ($hardness < 5 || $hardness > 31)
		{
			return null;
		}
		if ($hardness < 10)
		{
			$hardness = '0' . $hardness;
		}
	}
	else
	{
		return null;
	}
	$salt = '$2y$' . $hardness . '$' . $salt;
	$pwHash = crypt($password, $salt);
	if (substr($pwHash, 0, 7) !== substr($salt, 0, 7))
	{
		return null;
	}
	$k = hkdf($pwHash, $curve::getScalarByteSize(), 'tobtu.com ECSRP k');
	if (!isset($k))
	{
		return null;
	}
	return $curve::initScalar(gmp_init(bin2hex($k), 16));
}

/**
 * Converts a password into an inverted scalar.
 *
 * @param string $password
 * @param string $salt
 * @param string $curve
 * @param string $hardness
 * @return GMP|null
 */
function newPassword($password, $salt, $curve, $hardness = '09')
{
	$k = getScalarFromPassword($password, $salt, $curve, $hardness);
	if (!isset($k))
	{
		return null;
	}
	$kInv = $curve::invertScalar($k);
	$p = $curve::getP();
	$q = $curve::getQ();
	list($kInvPx, $kInvPy) = $curve::scalarMultiplyOutFull($kInv, $p[0], $p[1]);
	list($kInvQx, $kInvQy) = $curve::scalarMultiplyOutFull($kInv, $q[0], $q[1]);
	$kInvPx = padBigInt($kInvPx, $curve);
	$kInvPy = padBigInt($kInvPy, $curve);
	$kInvQx = padBigInt($kInvQx, $curve);
	$kInvQy = padBigInt($kInvQy, $curve);
	return array($kInvPx, $kInvPy, $kInvQx, $kInvQy);
}

/**
 * Time insensitive compare of two strings.
 *
 * @param string $a
 * @param string $b
 * @return bool
 */
function compareStr($a, $b)
{
	$cmpKey = mcrypt_create_iv(64, MCRYPT_DEV_URANDOM); // Never use MCRYPT_RAND
	return hash_hmac('sha256', $a, $cmpKey, true) === hash_hmac('sha256', $b, $cmpKey, true);
}

/**
 * Converts and pads a big int to the byte length for the $curve.
 *
 * @param GMP $gmp
 * @param string $curve
 * @return string
 */
function padBigInt($gmp, $curve)
{
	$str = gmp_strval($gmp, 16);
	$len = strlen($str);
	$size = 2 * $curve::getScalarByteSize();
	if ($size > $len)
	{
		return hex2bin(str_repeat('0', $size - $len) . $str);
	}
	return hex2bin(str_repeat('0', $len & 1) . $str);
}

/**
 * Client step 1.
 *
 * @param string $bkPx_kQx - X(bkP+kQ)
 * @param string $bkPy_kQy - Y(bkP+kQ)
 * @param string $password
 * @param string $salt
 * @param string $curve
 * @param string $hardness
 * @return array|null - On success array of strings (X(bP) || X(abP), X(aP), hash of (X(bP) || X(abP))), otherwise null
 */
function clientStep1($bkPx_kQx, $bkPy_kQy, $password, $salt, $curve, $hardness)
{
	// aP
	// k(b(1/k)P+(1/k)Q) - Q = bP
	// hash(bP || abP)

	// $a_priKey*P = $aPx
	// k*($bkPx_kQx,$bkPy_kQy) - Q = $bPx
	// hash($bPx || $a_priKey*$bPx)

	// aP
	$a_priKey = hkdf(mcrypt_create_iv(55, MCRYPT_DEV_URANDOM), $curve::getScalarByteSize(), 'tobtu.com ECSRP a'); // Never use MCRYPT_RAND
	if (!isset($a_priKey))
	{
		return null;
	}
	$a_priKey = $curve::initScalar(gmp_init(bin2hex($a_priKey), 16));
	$aPx = padBigInt($curve::scalarMultiplyOutPart($a_priKey, $curve::getPPart()), $curve);

	// k = pw hash
	$k = getScalarFromPassword($password, $salt, $curve, $hardness);
	if (!isset($k))
	{
		return null;
	}

	// Test point
	$bkPx_kQx = gmp_init(bin2hex($bkPx_kQx), 16);
	$bkPy_kQy = gmp_init(bin2hex($bkPy_kQy), 16);
	if (!$curve::isValidPoint($bkPx_kQx, $bkPy_kQy))
	{
		return null;
	}
	// k(b(1/k)P + (1/k)Q) = bP + Q
	list($tmpX, $tmpY) = $curve::scalarMultiplyOutFull($k, $bkPx_kQx, $bkPy_kQy);
	// (bP + Q) - Q = bP
	$q = $curve::getQ();
	$tmpX = $curve::subOutPart($tmpX, $tmpY, $q[0], $q[1]);
	$bPx  = padBigInt($tmpX, $curve);
	$abPx = $curve::scalarMultiplyOutPart($a_priKey, $tmpX);
	$abPx = padBigInt($abPx, $curve);
	return array($bPx . $abPx, $aPx, hash('sha256', $bPx . $abPx, true));
}

/**
 * Client step 2.
 *
 * @param string $aPx               - X(aP)
 * @param string $bPx_abPx          - X(bP) || X(abP)
 * @param string $hash_aPx_bPx_abPx - Hash of (X(aP) || X(bP) || X(abP))
 * @return bool
 */
function clientStep2($aPx, $bPx_abPx, $hash_aPx_bPx_abPx)
{
	// hash(aP || bP || abP) == $hash_aPx_bPx_abPx
	// hash($aPx || $bPx_abPx) == $hash_aPx_bPx_abPx

	$testVal = hash('sha256', $aPx . $bPx_abPx, true);
	return compareStr($hash_aPx_bPx_abPx, $testVal);
}

/**
 * Server step 1.
 *
 * @param string $kPx - X(kP)
 * @param string $kPy - Y(kP)
 * @param string $kQx - X(kQ)
 * @param string $kQy - Y(kQ)
 * @param string $curve
 * @return array|null - On success array of strings (private key b, X(bkP+kQ), Y(bkP+kQ)), otherwise null
 */
function serverStep1($kPx, $kPy, $kQx, $kQy, $curve)
{
	// b((1/k)P) + ((1/k)Q)
	// $b_priKey*($kPx,$kPy) + ($kQx,$kQy) = ($bkPx_kQx,$bkPy_kQy)

	$b_priKey = hkdf(mcrypt_create_iv(55, MCRYPT_DEV_URANDOM), $curve::getScalarByteSize(), 'tobtu.com ECSRP b'); // Never use MCRYPT_RAND
	if (!isset($b_priKey))
	{
		return null;
	}
	$b_priKey = $curve::initScalar(gmp_init(bin2hex($b_priKey), 16));
	// b((1/k)P)
	list($bkPx_kQx, $bkPy_kQy) = $curve::scalarMultiplyOutFull($b_priKey, gmp_init(bin2hex($kPx), 16), gmp_init(bin2hex($kPy), 16));
	// (b(1/k)P) + (1/k)Q
	list($bkPx_kQx, $bkPy_kQy) = $curve::addOutFull($bkPx_kQx, $bkPy_kQy, gmp_init(bin2hex($kQx), 16), gmp_init(bin2hex($kQy), 16));
	$bkPx_kQx = padBigInt($bkPx_kQx, $curve);
	$bkPy_kQy = padBigInt($bkPy_kQy, $curve);
	return array($b_priKey, $bkPx_kQx, $bkPy_kQy);
}

/**
 * Server step 2.
 *
 * @param string $b_priKey      - b
 * @param string $aPx           - X(aP)
 * @param string $hash_bPx_abPx - Hash of (X(bP) || X(abP))
 * @param string $curve
 * @return string|false - On success string of a hash of (X(aP) || X(bP) || X(abP)), otherwise false
 */
function serverStep2($b_priKey, $aPx, $hash_bPx_abPx, $curve)
{
	// hash(bP || abP) == $hash_bPx_abPx
	// hash($b_priKey*P || $b_priKey*$aPx) == $hash_bPx_abPx

	// bP
	$bPx = $curve::scalarMultiplyOutPart($b_priKey, $curve::getPPart());
	// b(aP)
	$abPx = $curve::scalarMultiplyOutPart($b_priKey, gmp_init(bin2hex($aPx), 16));

	$bPx  = padBigInt($bPx,  $curve);
	$abPx = padBigInt($abPx, $curve);
	$testVal = hash('sha256', $bPx . $abPx, true);
	if (!compareStr($hash_bPx_abPx, $testVal))
	{
		return false;
	}
	return hash('sha256', $aPx . $bPx . $abPx, true);
}


// *** Client ***
// *** C->S: user ***

// *** Server ***
// \/ \/ \/ look up user *cough* *cough* \/ \/ \/
$curve    = 'Curve25519';
$salt     = '......................';
$hardness = '09';
$ret = newPassword('password', $salt, $curve, $hardness);
if (!isset($ret))
{
	die('Error creating password failed');
}
list($kPx, $kPy, $kQx, $kQy) = $ret;
// /\ /\ /\ look up user *cough* *cough* /\ /\ /\
$ret = serverStep1($kPx, $kPy, $kQx, $kQy, $curve);
if (!isset($ret))
{
	die("*** Server ***\nSomething failed");
}
list($b_priKey, $bkPx_Qx, $bkPy_kQy) = $ret;
echo "*** Server ***\n";
echo 'b        = ' . bin2hex(padBigInt($b_priKey, $curve)) . "\n";
echo ' kP      = (' . bin2hex($kPx) . ', ' . bin2hex($kPy) . ")\n";
echo '      kQ = (' . bin2hex($kQx) . ', ' . bin2hex($kQy) . ")\n";
echo 'bkP + kQ = (' . bin2hex($bkPx_Qx) . ', ' . bin2hex($bkPy_kQy) . ")\n\n";
// *** C<-S: $bkPx_Qx, $bkPy_kQy, $salt, $hardness ***

// *** Client ***
$ret = clientStep1($bkPx_Qx, $bkPy_kQy, 'password', $salt, $curve, $hardness);
if (!isset($ret))
{
	die("*** Client ***\nSomething failed");
}
list($bPx_abPx, $aPx, $hash_bPx_abPx) = $ret;
echo "*** Client ***\n";
echo '  X(aP)                     = ' . bin2hex($aPx) . "\n";
echo '           X(bP)            = ' . bin2hex(substr($bPx_abPx, 0, $curve::getScalarByteSize())) . "\n";
echo '                    X(abP)  = ' . bin2hex(substr($bPx_abPx, $curve::getScalarByteSize())) . "\n";
echo 'H(         X(bP) || X(abP)) = ' . bin2hex($hash_bPx_abPx) . "\n\n";
// *** C->S: $aPx, $hash_bPx_abPx ***

// *** Server ***
$hash_aPx_bPx_abPx = serverStep2($b_priKey, $aPx, $hash_bPx_abPx, $curve);
if ($hash_aPx_bPx_abPx === false)
{
	die("*** Server ***\nBye client (bad password)");
}
echo "*** Server ***\n";
echo 'H(X(aP) || X(bP) || X(abP)) = ' . bin2hex($hash_aPx_bPx_abPx) . "\n\n";
// *** C<-S: $hash_aPx_bPx_abPx ***

// *** Client ***
if (clientStep2($aPx, $bPx_abPx, $hash_aPx_bPx_abPx) === false)
{
	die("*** Client ***\nBye server (evil server)");
}

// *** Both ***
die("*** Both ***\nEverything worked");
