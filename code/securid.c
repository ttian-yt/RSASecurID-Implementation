/*==============================================================================
! RSA SecurID Implementation (Simplified/Insecure)
! Simplified RSA SecurID for Learning Purposes
! Supports two factor authentication and timer synchronisation of ONE user only.
!
! SecurID: Algorithmic computation
!
! Date: 7th April 2020
! Author: Yutian (Yolanda) Li
==============================================================================*/


#include "securid.h"

/* 
 * Generate authentication code using seed and time
 * Returns authentication code
 */
int generate_authentication_code(int seed, int curr_time) {
	return curr_time + seed;
}

//NOTE: int32_t 32bit integer, supports at least 6 digits