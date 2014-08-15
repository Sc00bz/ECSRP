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

class Curve25519
{
	/**
	 * 2^255 - 19
	 *
	 * @access private
	 * @var resource (gmp)
	 */
	private static $p25519;

	/**
	 * Used to for modular exponentiation to calculate the modular inverse of 2^255 - 19. (2^255 - 19 - 2)
	 *
	 * @access private
	 * @var resource (gmp)
	 */
	private static $p25519InvertPow;

	/**
	 * Used by sqrtMod25519() to calculate the modular square root. (2^252 - 2)
	 *
	 * @access private
	 * @var resource (gmp)
	 */
	private static $n252M2;

	/**
	 * Used by sqrtMod25519() to calculate the modular square root.
	 *
	 * @access private
	 * @var resource (gmp)
	 */
	private static $sqrtConst;

	/**
	 * The cyclical group's order.
	 *
	 * @access private
	 * @var resource (gmp)
	 */
	private static $cyclicalGroupOrder;

	/**
	 * Used to for modular exponentiation to calculate the modular inverse of the cyclical group's order.
	 *
	 * @access private
	 * @var resource (gmp)
	 */
	private static $cyclicalGroupOrderInvertPow;

	/**
	 * Used by initScalar() to get the scalar in the correct range.
	 *
	 * @access private
	 * @var resource (gmp)
	 */
	private static $scalarMask;


	// *****************************
	// *****************************
	// ****  Private functions  ****
	// *****************************
	// *****************************

	/**
	 * Used by scalarMultiplyOutPart() to add two partial points.
	 *
	 * @access private
	 * @param GMP $baseX
	 * @param GMP $xPz
	 * @param GMP $xMz
	 * @param GMP $x2Pz2
	 * @param GMP $x2Mz2
	 * @param GMP &$retX
	 * @param GMP &$retZ
	 */
	private static function addDiffX($baseX, $xPz, $xMz, $x2Pz2, $x2Mz2, &$retX, &$retZ)
	{
		// retX = ((x-z) * (x'+z') + (x+z) * (x'-z'))^2 * 1
		// retZ = ((x-z) * (x'+z') - (x+z) * (x'-z'))^2 * x1

		// $tmp1 = $xMz * $x2Pz2
		// $tmp2 = $xPz * $x2Mz2
		// $retX = ($tmp1 + $tmp2)^2
		// $retZ = ($tmp1 - $tmp2)^2 * $baseX
		$tmp1 = gmp_mod(gmp_mul($xMz, $x2Pz2), Curve25519::$p25519);
		$tmp2 = gmp_mod(gmp_mul($xPz, $x2Mz2), Curve25519::$p25519);
		$retX = gmp_powm(gmp_add($tmp1, $tmp2), 2, Curve25519::$p25519);
		// See if (a-b)^2 (mod c) = ((a-b) (mod c)) ^ 2 (mod c)
		$retZ = gmp_sub($tmp1, $tmp2);
		if (gmp_sign($retZ) < 0)
		{
			$retZ = gmp_add($retZ, Curve25519::$p25519);
		}
		$retZ = gmp_powm($retZ, 2, Curve25519::$p25519);
		$retZ = gmp_mod(gmp_mul($retZ, $baseX), Curve25519::$p25519);
	}

	/**
	 * Used by scalarMultiplyOutPart() to double a partial point.
	 *
	 * @access private
	 * @param GMP $xPz
	 * @param GMP $xMz
	 * @param GMP &$retX
	 * @param GMP &$retZ
	 */
	private static function doubleDiffX($xPz, $xMz, &$retX, &$retZ)
	{
		// x2 = (x-z)^2 * (x+z)^2
		// z2 = ((x+z)^2 - (x-z)^2) * ((x+z)^2 + (A-2)/4*((x+z)^2 - (x-z)^2))

		// $xMzP2 = $xMz^2
		// $xPzP2 = $xPz^2
		// $xPzP2_M_xMzP2 = $xPzP2 - $xMzP2
		// $retX = $xMzP2 * $xPzP2
		// $retZ = $xPzP2_M_xMzP2 * ($xPzP2 + 0x1db41 * $xPzP2_M_xMzP2)
		$xMzP2 = gmp_powm($xMz, 2, Curve25519::$p25519);
		$xPzP2 = gmp_powm($xPz, 2, Curve25519::$p25519);
		$xPzP2_M_xMzP2 = gmp_sub($xPzP2, $xMzP2);
		$retX = gmp_mod(gmp_mul($xMzP2, $xPzP2), Curve25519::$p25519);
		// To do: find fastest order
		$retZ = gmp_mod(gmp_add($xPzP2, gmp_mul(0x1db41, $xPzP2_M_xMzP2)), Curve25519::$p25519);
		$retZ = gmp_mod(gmp_mul($retZ, $xPzP2_M_xMzP2), Curve25519::$p25519);
	}

	/**
	 * Square root modulo 2^255-19.
	 *
	 * @access private
	 * @param GMP $n
	 * @return GMP|false
	 */
	private static function sqrtMod25519($n)
	{
		$tmp = gmp_powm($n, Curve25519::$n252M2, Curve25519::$p25519);
		if (gmp_cmp(gmp_mod(gmp_mul($tmp, $tmp), Curve25519::$p25519), $n) !== 0)
		{
			$tmp = gmp_mod(gmp_mul($tmp, Curve25519::$sqrtConst), Curve25519::$p25519);
			if (gmp_cmp(gmp_mod(gmp_mul($tmp, $tmp), Curve25519::$p25519), $n) !== 0)
			{
				return false;
			}
		}
		return $tmp;
	}

	/**
	 * Returns the Y coordinate from an X coordinate.
	 *
	 * @access private
	 * @param GMP $x
	 * @return GMP|false
	 */
	private static function getXFromY($x)
	{
		// y^2 = x^3 + 486662 * x^2 + x
		$xx  = gmp_mod(gmp_mul($x,   $x    ), Curve25519::$p25519);
		$xxx = gmp_mod(gmp_mul($xx,  $x    ), Curve25519::$p25519);
		$tmp = gmp_mod(gmp_mul($xx,  486662), Curve25519::$p25519);
		$tmp =         gmp_add($xxx, $tmp  );
		$tmp = gmp_mod(gmp_add($tmp, $x    ), Curve25519::$p25519);
		return Curve25519::sqrtMod25519($tmp);
	}


	// ****************************
	// ****************************
	// ****  Public functions  ****
	// ****************************
	// ****************************

	/**
	 * Initialize constants.
	 *
	 * @access public
	 */
	public static function init()
	{
		if (!isset(Curve25519::$p25519))
		{
			Curve25519::$p25519                      = gmp_init('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed', 16);
			Curve25519::$p25519InvertPow             = gmp_init('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb', 16);
			Curve25519::$n252M2                      = gmp_init( 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe', 16);
			Curve25519::$sqrtConst                   = gmp_init('2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0', 16);
			Curve25519::$cyclicalGroupOrder          = gmp_init('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed', 16);
			Curve25519::$cyclicalGroupOrderInvertPow = gmp_init('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3eb', 16);
			Curve25519::$scalarMask                  = gmp_init('7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8', 16);
		}
	}

	/**
	 * Add two points and return the full point.
	 *
	 * @access public
	 * @param GMP $pX
	 * @param GMP $pY
	 * @param GMP $qX
	 * @param GMP $qY
	 * @return array(GMP $x, GMP $y)
	 */
	public static function addOutFull($pX, $pY, $qX, $qY)
	{
		// s = (P_y - Q_y) / (P_x - Q_x)
		$s   = gmp_sub($pY, $qY);
		$tmp = gmp_sub($pX, $qX);
		$tmp = gmp_powm($tmp, Curve25519::$p25519InvertPow, Curve25519::$p25519);
		$s   = gmp_mod(gmp_mul($s, $tmp), Curve25519::$p25519);

		// b = P_x + Q_x + A
		$b = gmp_add(gmp_add($pX, $qX), 486662);

		// X(P + Q) = s ^ 2 - b
		$retX = gmp_mod(gmp_sub(gmp_mul($s, $s), $b), Curve25519::$p25519);

		// Y(P + Q) = s * (P_x - X(P + Q)) - P_y
		$retY = gmp_mod(gmp_sub(gmp_mul(gmp_sub($pX, $retX), $s), $pY), Curve25519::$p25519);

		return array($retX, $retY);
	}

	/**
	 * Double a point and return the full point.
	 *
	 * @access public
	 * @param GMP $x
	 * @param GMP $y
	 * @return array(GMP $x, GMP $y)
	 */
	public static function doubleOutFull($x, $y)
	{
		// s = (3 * x ^ 2 + 2 * x * A + 1) / (2 * y)
		$tmp = gmp_mod(gmp_mul($x, $x), Curve25519::$p25519);
		$s   = gmp_add(gmp_add($tmp, $tmp), $tmp);
		$tmp = gmp_mod(gmp_mul($x, 973324), Curve25519::$p25519);
		$s   = gmp_add(gmp_add($s, $tmp), 1);
		$tmp = gmp_powm(gmp_add($y, $y), Curve25519::$p25519InvertPow, Curve25519::$p25519);
		$s   = gmp_mod(gmp_mul($s, $tmp), Curve25519::$p25519);

		// X(2 * P) = s ^ 2 - 2 * x - A
		$tmp = gmp_mod(gmp_mul($s, $s), Curve25519::$p25519);
		$tmp = gmp_sub(gmp_sub($tmp, $x), $x);
		$retX = gmp_mod(gmp_sub($tmp, 486662), Curve25519::$p25519);

		// Y(2 * P) = (x - X(2 * P)) * s - y
		$tmp = gmp_mul(gmp_sub($x, $retX), $s);
		$retY = gmp_mod(gmp_sub($tmp, $y), Curve25519::$p25519);

		return array($retX, $retY);
	}

	/**
	 * Subtract two points and return a partial point.
	 *
	 * @access public
	 * @param GMP $pX
	 * @param GMP $pY
	 * @param GMP $qX
	 * @param GMP $qY
	 * @return GMP
	 */
	public static function subOutPart($pX, $pY, $qX, $qY)
	{
		// s = (P_y - -Q_y) / (P_x - Q_x)
		$s   = gmp_add($pY, $qY);
		$tmp = gmp_sub($pX, $qX);
		$tmp = gmp_powm($tmp, Curve25519::$p25519InvertPow, Curve25519::$p25519);
		$s   = gmp_mod(gmp_mul($s, $tmp), Curve25519::$p25519);

		// b = P_x + Q_x + A
		$b = gmp_add(gmp_add($pX, $qX), 486662);

		// X(P + Q) = s ^ 2 - b
		$retX = gmp_mod(gmp_sub(gmp_mul($s, $s), $b), Curve25519::$p25519);

		return $retX;
	}

	/**
	 * Scalar, (partial) point multiplication.
	 *
	 * @access public
	 * @param GMP $scalar
	 * @param GMP $baseX
	 * @return GMP
	 */
	public static function scalarMultiplyOutPart($scalar, $baseX)
	{
		// Init
		$x1 = 1;
		$z1 = 0;
		$x2 = $baseX;
		$z2 = 1;

		for ($i = 254; $i >= 0; $i--)
		{
			$xPz   = gmp_add($x1, $z1);
			$xMz   = gmp_sub($x1, $z1);
			$x2Pz2 = gmp_add($x2, $z2);
			$x2Mz2 = gmp_sub($x2, $z2);
			if (gmp_testbit($scalar, $i))
			{
				Curve25519::addDiffX($baseX, $xPz, $xMz, $x2Pz2, $x2Mz2, $x1, $z1);
				Curve25519::doubleDiffX($x2Pz2, $x2Mz2, $x2, $z2);
			}
			else
			{
				Curve25519::addDiffX($baseX, $xPz, $xMz, $x2Pz2, $x2Mz2, $x2, $z2);
				Curve25519::doubleDiffX($xPz, $xMz, $x1, $z1);
			}
		}

		return gmp_mod(gmp_mul(gmp_powm($z1, Curve25519::$p25519InvertPow, Curve25519::$p25519), $x1), Curve25519::$p25519);
	}


	/**
	 * Scalar, (full) point multiplication.
	 *
	 * @access public
	 * @param GMP $scalar
	 * @param GMP $baseX
	 * @param GMP $baseY
	 * @return array(GMP $x, GMP $y)
	 */
	public static function scalarMultiplyOutFull($scalar, $baseX, $baseY)
	{
		// Init
		$isZero = true;
		$retX = 0;
		$retY = 1;

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
					list($retX, $retY) = Curve25519::addOutFull($retX, $retY, $baseX, $baseY);
				}
			}
			list($baseX, $baseY) = Curve25519::doubleOutFull($baseX, $baseY);
		}

		return array($retX, $retY);
	}

	/**
	 * Modular inverts a scalar in respect to the order of the cyclical group.
	 *
	 * @access public
	 * @return GMP
	 */
	public static function invertScalar($scalar)
	{
		return gmp_powm($scalar, Curve25519::$cyclicalGroupOrderInvertPow, Curve25519::$cyclicalGroupOrder);
	}

	/**
	 * Converts raw getScalarByteSize() bytes as a gmp resource into a proper scalar.
	 *
	 * @access public
	 * @return GMP
	 */
	public static function initScalar($scalar)
	{
		$ret = gmp_and($scalar, Curve25519::$scalarMask);
		gmp_setbit($ret, 254);
		return $ret;
	}

	/**
	 * Returns the size of the private key in bytes.
	 *
	 * @access public
	 * @return int
	 */
	public static function getScalarByteSize()
	{
		return 32;
	}

	/**
	 * Returns the P point.
	 *
	 * @access public
	 * @return array(GMP $x, GMP $y)
	 */
	public static function getP()
	{
		// P = (0x09, 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9)
		return array(gmp_init('9', 16), gmp_init('20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9', 16));
	}

	/**
	 * Returns part of the P point.
	 *
	 * @access public
	 * @return GMP
	 */
	public static function getPPart()
	{
		// P = (0x09, 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9)
		return gmp_init('9', 16);
	}

	/**
	 * Returns the Q point.
	 *
	 * @access public
	 * @return array(GMP $x, GMP $y)
	 */
	public static function getQ()
	{
		// Q = (0x10, 0x36b20194b9ee7885e888642d2006d60cdcc836d17f615e8416989556b3941598)
		return array(gmp_init('10', 16), gmp_init('36b20194b9ee7885e888642d2006d60cdcc836d17f615e8416989556b3941598', 16));
	}

	/**
	 * Checks is a point is valid.
	 *
	 * @access public
	 * @param GMP $x
	 * @param GMP $y
	 * @return bool
	 */
	public static function isValidPoint($x, $y)
	{
		if (
			gmp_cmp(Curve25519::$p25519, $x) > 0 &&
			gmp_cmp(Curve25519::$p25519, $y) > 0 &&
			gmp_sign($x) > 0 &&
			gmp_sign($y) > 0)
		{
			$testY = Curve25519::getXFromY($x);
			if (
				$testY !== false &&
				((gmp_cmp($y, $testY) === 0 ||
				  gmp_cmp($y, gmp_sub(Curve25519::$p25519, $testY)) === 0) &&
				 gmp_sign(Curve25519::scalarMultiplyOutPart(Curve25519::$cyclicalGroupOrder, $x)) === 0))
			{
				return true;
			}
		}
		return false;
	}
};

Curve25519::init();
