<?php

header("Content-type: text/plain");

// P = (0x09, 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9)
// Q = (0x10, 0x36b20194b9ee7885e888642d2006d60cdcc836d17f615e8416989556b3941598)

// 2^255 - 19
$p25519    = gmp_init('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed', 16);
// 2^255 - 19 - 2
$p25519M2  = gmp_init('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb', 16);
// 2^252 - 2
$n252M2    = gmp_init( 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe', 16);
$sqrtConst = gmp_init('2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0', 16);
$cyclicalGroupOrder   = gmp_init('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed', 16);
$cyclicalGroupOrderM2 = gmp_init('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3eb', 16);

function curve25519Add($pointX, $xPz, $xMz, $x2Pz2, $x2Mz2, &$retX, &$retZ)
{
	global $p25519;

	// retX = ((x-z) * (x'+z') + (x+z) * (x'-z'))^2 * 1
	// retZ = ((x-z) * (x'+z') - (x+z) * (x'-z'))^2 * x1

	// $tmp1 = $xMz * $x2Pz2
	// $tmp2 = $xPz * $x2Mz2
	// $retX = ($tmp1 + $tmp2)^2
	// $retZ = ($tmp1 - $tmp2)^2 * $pointX
	$tmp1 = gmp_mod(gmp_mul($xMz, $x2Pz2), $p25519);
	$tmp2 = gmp_mod(gmp_mul($xPz, $x2Mz2), $p25519);
	$retX = gmp_powm(gmp_add($tmp1, $tmp2), 2, $p25519);
	// See if (a-b)^2 (mod c) = ((a-b) (mod c)) ^ 2 (mod c)
	$retZ = gmp_sub($tmp1, $tmp2);
	if (gmp_sign($retZ) < 0)
	{
		$retZ = gmp_add($retZ, $p25519);
	}
	$retZ = gmp_powm($retZ, 2, $p25519);
	$retZ = gmp_mod(gmp_mul($retZ, $pointX), $p25519);
}

function curve25519Double($xPz, $xMz, &$retX, &$retZ)
{
	global $p25519;

	// x2 = (x-z)^2 * (x+z)^2
	// z2 = ((x+z)^2 - (x-z)^2) * ((x+z)^2 + (A-2)/4*((x+z)^2 - (x-z)^2))

	// $xMzP2 = $xMz^2
	// $xPzP2 = $xPz^2
	// $xPzP2_M_xMzP2 = $xPzP2 - $xMzP2
	// $retX = $xMzP2 * $xPzP2
	// $retZ = $xPzP2_M_xMzP2 * ($xPzP2 + 0x1db41 * $xPzP2_M_xMzP2)
	$xMzP2 = gmp_powm($xMz, 2, $p25519);
	$xPzP2 = gmp_powm($xPz, 2, $p25519);
	$xPzP2_M_xMzP2 = gmp_sub($xPzP2, $xMzP2);
	$retX = gmp_mod(gmp_mul($xMzP2, $xPzP2), $p25519);
	// To do: find fastest order
	$retZ = gmp_mod(gmp_add($xPzP2, gmp_mul(0x1db41, $xPzP2_M_xMzP2)), $p25519);
	$retZ = gmp_mod(gmp_mul($retZ, $xPzP2_M_xMzP2), $p25519);
}

function curve25519AddOutXY($pX, $pY, $qX, $qY)
{
	global $p25519;
	global $p25519M2;

	// s = (P_y - Q_y) / (P_x - Q_x)
	$s   = gmp_sub($pY, $qY);
	$tmp = gmp_sub($pX, $qX);
	$tmp = gmp_powm($tmp, $p25519M2, $p25519);
	$s   = gmp_mod(gmp_mul($s, $tmp), $p25519);

	// b = P_x + Q_x + A
	$b = gmp_add(gmp_add($pX, $qX), 486662);

	// X(P + Q) = s ^ 2 - b
	$retX = gmp_mod(gmp_sub(gmp_mul($s, $s), $b), $p25519);

	// Y(P + Q) = s * (P_x - X(P + Q)) - P_y
	$retY = gmp_mod(gmp_sub(gmp_mul(gmp_sub($pX, $retX), $s), $pY), $p25519);

	return array($retX, $retY);
}

function curve25519DoubleOutXY($x, $y)
{
	global $p25519;
	global $p25519M2;

	// s = (3 * x ^ 2 + 2 * x * A + 1) / (2 * y)
	$tmp = gmp_mod(gmp_mul($x, $x), $p25519);
	$s   = gmp_add(gmp_add($tmp, $tmp), $tmp);
	$tmp = gmp_mod(gmp_mul($x, 973324), $p25519);
	$s   = gmp_add(gmp_add($s, $tmp), 1);
	$tmp = gmp_powm(gmp_add($y, $y), $p25519M2, $p25519);
	$s   = gmp_mod(gmp_mul($s, $tmp), $p25519);

	// X(2 * P) = s ^ 2 - 2 * x - A
	$tmp = gmp_mod(gmp_mul($s, $s), $p25519);
	$tmp = gmp_sub(gmp_sub($tmp, $x), $x);
	$retX = gmp_mod(gmp_sub($tmp, 486662), $p25519);

	// Y(2 * P) = (x - X(2 * P)) * s - y
	$tmp = gmp_mul(gmp_sub($x, $retX), $s);
	$retY = gmp_mod(gmp_sub($tmp, $y), $p25519);

	return array($retX, $retY);
}

function curve25519Ecdh($scalar, $pointHex = '9')
{
	global $p25519;
	global $p25519M2;

	// Init
	$pointX = gmp_init($pointHex, 16);
	$x1 = 1;
	$z1 = 0;
	$x2 = $pointX;
	$z2 = 1;

	for ($i = 254; $i >= 0; $i--)
	{
		$xPz   = gmp_add($x1, $z1);
		$xMz   = gmp_sub($x1, $z1);
		$x2Pz2 = gmp_add($x2, $z2);
		$x2Mz2 = gmp_sub($x2, $z2);
		if (gmp_testbit($scalar, $i))
		{
			curve25519Add($pointX, $xPz, $xMz, $x2Pz2, $x2Mz2, $x1, $z1);
			curve25519Double($x2Pz2, $x2Mz2, $x2, $z2);
		}
		else
		{
			curve25519Add($pointX, $xPz, $xMz, $x2Pz2, $x2Mz2, $x2, $z2);
			curve25519Double($xPz, $xMz, $x1, $z1);
		}
	}

	return gmp_mod(gmp_mul(gmp_powm($z1, $p25519M2, $p25519), $x1), $p25519);
}

function curve25519EcdhOutXY($scalar, $pointXHex = '9', $pointYHex = '20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9')
{
	// Init
	$baseX = gmp_init($pointXHex, 16);
	$baseY = gmp_init($pointYHex, 16);
	$isZero = true;
	$retX = 0;
	$retY = 0;

	for ($i = 0; $i < 255; $i++)
	{
		if (gmp_testbit($scalar, $i))
		{
			if ($isZero)
			{
				$isZero = false;
				$retX = $baseX;
				$retY = $baseY;
			}
			else
			{
				list($retX, $retY) = curve25519AddOutXY($retX, $retY, $baseX, $baseY);
			}
		}
		list($baseX, $baseY) = curve25519DoubleOutXY($baseX, $baseY);
	}

	return array($retX, $retY);
}

function curve25519InvertScalar($scalar)
{
	global $cyclicalGroupOrderM2;
	global $cyclicalGroupOrder;

	return gmp_powm($scalar, $cyclicalGroupOrderM2, $cyclicalGroupOrder);
}

function hkdf($inputKeyingMaterial, $keySize, $info = '', $salt = null, $algo = 'sha256')
{
	$hmacSize = strlen(hash_hmac($algo, '', '')) / 2;
	if ($keySize > $hmacSize * 255)
	{
		return null;
	}
	if (!isset($salt))
	{
		$salt = str_repeat("\0", $hmacSize);
	}
	$extractedKey = hash_hmac($algo, $salt, $inputKeyingMaterial, true);
	$keyLen = 0;
	$key = str_repeat("\0", $hmacSize);
	for ($i = 1; $keyLen < $keySize; $i++)
	{
		$key .= hash_hmac($algo, substr($key, -$hmacSize) . $info . chr($i), $extractedKey, true);
		$keyLen += $hmacSize;
	}
	return substr($key, $hmacSize, $keySize);
}

function getScalarFromPassword($password, $salt, $hardness = '09')
{
	if (is_string($hardness))
	{
		if (strlen($hardness) === 1)
		{
			$hardness = '0' . $hardness;
		}
		else if (strlen($hardness) > 2)
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
	else if(is_int($hardness))
	{
		if ($hardness < 5 || $hardness > 31)
		{
			return null;
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
	$x = hkdf($pwHash, 32, 'tobtu.com ECSRP x');
	if (!isset($x))
	{
		return null;
	}
	$x = gmp_init(bin2hex($x), 16);
	gmp_clrbit($x, 255);
	gmp_setbit($x, 254);
	gmp_clrbit($x, 2);
	gmp_clrbit($x, 1);
	gmp_clrbit($x, 0);
	return $x;
}

function newPassword($password, $salt, $hardness = '09')
{
	$x = getScalarFromPassword($password, $salt, $hardness);
	if (!isset($x))
	{
		return null;
	}
	$x = curve25519InvertScalar($x);
	list($xP_x, $xP_y) = curve25519EcdhOutXY($x,  '9', '20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9');
	list($xQ_x, $xQ_y) = curve25519EcdhOutXY($x, '10', '36b20194b9ee7885e888642d2006d60cdcc836d17f615e8416989556b3941598');
	$xP_x = gmp_strval($xP_x, 16);
	$xP_y = gmp_strval($xP_y, 16);
	$xQ_x = gmp_strval($xQ_x, 16);
	$xQ_y = gmp_strval($xQ_y, 16);
	return array($xP_x, $xP_y, $xQ_x, $xQ_y);
}

function compareStr($a, $b)
{
	$cmpKey = hkdf(mcrypt_create_iv(55, MCRYPT_DEV_URANDOM), 32, 'tobtu.com ECSRP cmp'); // Never use MCRYPT_RAND
	return hash_hmac('sha256', $a, $cmpKey, true) === hash_hmac('sha256', $b, $cmpKey, true);
}

function clientStep1($bxP_xQ_x, $bxP_xQ_y, $password, $salt, $hardness)
{
	// aP
	// x(b(1/x)P+(1/x)Q) - Q + P = (b+1)P
	// hash((b+1)P || a(b+1)P)

	// $a_priKey*P = $aP_pubKey
	// x*($bxP_xQ_x,$bxP_xQ_y) - Q + P = $bP_x
	// hash($bP_x || $a_priKey*$bP_x)

	global $p25519;

	// aP
	$a_priKey = hkdf(mcrypt_create_iv(55, MCRYPT_DEV_URANDOM), 32, 'tobtu.com ECSRP a'); // Never use MCRYPT_RAND
	if (!isset($a_priKey))
	{
		return null;
	}
	$a_priKey = gmp_init(bin2hex($a_priKey), 16);
	gmp_clrbit($a_priKey, 255);
	gmp_setbit($a_priKey, 254);
	gmp_clrbit($a_priKey, 2);
	gmp_clrbit($a_priKey, 1);
	gmp_clrbit($a_priKey, 0);
	$aP_pubKey = gmp_strval(curve25519Ecdh($a_priKey), 16);

	// x = pw hash
	$x = getScalarFromPassword($password, $salt, $hardness);
	if (!isset($x))
	{
		return null;
	}
	// x(b(1/x)P + (1/x)Q) = bP + Q
	list($tmpX, $tmpY) = curve25519EcdhOutXY($x, $bxP_xQ_x, $bxP_xQ_y);
	// (bP + Q) - Q = bP
	list($tmpX, $tmpY) = curve25519AddOutXY($tmpX, $tmpY, 0x10, gmp_sub($p25519, gmp_init('36b20194b9ee7885e888642d2006d60cdcc836d17f615e8416989556b3941598', 16)));
	// (bP) + P = (b+1)P
	list($tmpX, $tmpY) = curve25519AddOutXY($tmpX, $tmpY, 0x9, gmp_init('20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9', 16));
	$bP_x  = gmp_strval($tmpX, 16);
	$abP_x = curve25519Ecdh($a_priKey, $bP_x);

	$bP_x  = str_repeat('0', 64 - strlen($bP_x)) . $bP_x;
	$abP_x = gmp_strval($abP_x, 16);
	$abP_x = str_repeat('0', 64 - strlen($abP_x)) . $abP_x;
	return array($bP_x . $abP_x, $aP_pubKey, hash('sha256', $bP_x . $abP_x));
}

function clientStep2($aP_pubKey, $bPx_abPx, $hash_aPx_bPx_abPx)
{
	// hash(aP || (b+1)P || a(b+1)P) == $hash_aPx_bPx_abPx
	// hash($aP_pubKey || $bPx_abPx) == $hash_aPx_bPx_abPx

	$aP_pubKey  = str_repeat('0', 64 - strlen($aP_pubKey)) . $aP_pubKey;
	$testVal = hash('sha256', $aP_pubKey . $bPx_abPx);
	if (!compareStr($hash_aPx_bPx_abPx, $testVal))
	{
		return false;
	}
	return true;
}

function serverStep1($xP_x, $xP_y, $xQ_x, $xQ_y)
{
	// b((1/x)P) + ((1/x)Q)
	// $b_priKey*($xP_x,$xP_y) + ($xQ_x,$xQ_y) = ($bxP_xQ_x,$bxP_xQ_y)

	$b_priKey = hkdf(mcrypt_create_iv(55, MCRYPT_DEV_URANDOM), 32, 'tobtu.com ECSRP b'); // Never use MCRYPT_RAND
	if (!isset($b_priKey))
	{
		return null;
	}
	$b_priKey = gmp_init(bin2hex($b_priKey), 16);
	gmp_clrbit($b_priKey, 255);
	gmp_setbit($b_priKey, 254);
	gmp_clrbit($b_priKey, 2);
	gmp_clrbit($b_priKey, 1);
	gmp_clrbit($b_priKey, 0);
	// b((1/x)P)
	list($bxP_xQ_x, $bxP_xQ_y) = curve25519EcdhOutXY($b_priKey, $xP_x, $xP_y);
	// (b(1/x)P) + (1/x)Q
	list($bxP_xQ_x, $bxP_xQ_y) = curve25519AddOutXY($bxP_xQ_x, $bxP_xQ_y, gmp_init($xQ_x, 16), gmp_init($xQ_y, 16));
	$bxP_xQ_x = gmp_strval($bxP_xQ_x, 16);
	$bxP_xQ_y = gmp_strval($bxP_xQ_y, 16);
	return array($b_priKey, $bxP_xQ_x, $bxP_xQ_y);
}

function serverStep2($b_priKey, $aP_pubKey, $hash_bPx_abPx)
{
	// hash((b+1)P || a(b+1)P) == $hash_bPx_abPx
	// hash(($b_priKey+1)P || ($b_priKey+1)*$aP_pubKey) == $hash_bPx_abPx

	// b_priKey = b+1
	$b_priKey = gmp_add($b_priKey, 1);

	// (b+1)P
	$bP_x = curve25519Ecdh($b_priKey);
	// (b+1)(aP)
	$abP_x = curve25519Ecdh($b_priKey, $aP_pubKey);

	$bP_x  = gmp_strval($bP_x, 16);
	$bP_x  = str_repeat('0', 64 - strlen($bP_x)) . $bP_x;
	$abP_x = gmp_strval($abP_x, 16);
	$abP_x = str_repeat('0', 64 - strlen($abP_x)) . $abP_x;
	$testVal = hash('sha256', $bP_x . $abP_x);
	if (!compareStr($hash_bPx_abPx, $testVal))
	{
		return false;
	}
	$aP_pubKey = str_repeat('0', 64 - strlen($aP_pubKey)) . $aP_pubKey;
	return hash('sha256', $aP_pubKey . $bP_x . $abP_x);
}


// *** Client ***
// *** C->S: user ***

// *** Server ***
// \/ \/ \/ look up user *cough* *cough* \/ \/ \/
$salt = '......................';
$hardness = '09';
list($xP_x, $xP_y, $xQ_x, $xQ_y) = newPassword('password', $salt, $hardness = '09');
// /\ /\ /\ look up user *cough* *cough* /\ /\ /\
list($b_priKey, $bxP_xQ_x, $bxP_xQ_y) = serverStep1($xP_x, $xP_y, $xQ_x, $xQ_y);
echo "*** Server ***\n";
echo "xP       = ($xP_x, $xP_y)\n";
echo "xQ       = ($xQ_x, $xQ_y)\n";
echo "b        = " . gmp_strval($b_priKey, 16) . "\n";
echo "bxP + xQ = ($bxP_xQ_x, $bxP_xQ_y)\n\n";
// *** C<-S: $bxP_xQ_x, $bxP_xQ_y, $salt, $hardness ***

// *** Client ***
list($bPx_abPx, $aP_pubKey, $hash_bPx_abPx) = clientStep1($bxP_xQ_x, $bxP_xQ_y, 'password', $salt, $hardness);
echo "*** Client ***\n";
echo "X(aP)                      = $aP_pubKey\n";
echo "  X((b+1)P)                = " . substr($bPx_abPx, 0, 64) . "\n";
echo "               X(a(b+1)P)  = " . substr($bPx_abPx, 64) . "\n";
echo "H(X((b+1)P) || X(a(b+1)P)) = $hash_bPx_abPx\n\n";
// *** C->S: $aP_pubKey, $hash_bPx_abPx ***

// *** Server ***
$hash_aPx_bPx_abPx = serverStep2($b_priKey, $aP_pubKey, $hash_bPx_abPx);
if ($hash_aPx_bPx_abPx === false)
{
	die("*** Server ***\nBye client (bad password)");
}
echo "*** Server ***\n";
echo "H(X(aP) || X((b+1)P) || X(a(b+1)P)) = $hash_aPx_bPx_abPx\n\n";
// *** C<-S: $hash_aPx_bPx_abPx ***

// *** Client ***
if (clientStep2($aP_pubKey, $bPx_abPx, $hash_aPx_bPx_abPx) === false)
{
	die("*** Client ***\nBye server (evil server)");
}

// *** Both ***
die("*** Both ***\nEverything worked");
