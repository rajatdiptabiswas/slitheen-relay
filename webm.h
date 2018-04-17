/* Slitheen - a decoy routing system for censorship resistance
 * Copyright (C) 2018 Cecylia Bocovich (cbocovic@uwaterloo.ca)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7
 *
 * If you modify this Program, or any covered work, by linking or combining
 * it with the OpenSSL library (or a modified version of that library),
 * containing parts covered by the terms of the OpenSSL Licence and the
 * SSLeay license, the licensors of this Program grant you additional
 * permission to convey the resulting work. Corresponding Source for a
 * non-source form of such a combination shall include the source code
 * for the parts of the OpenSSL library used as well as that of the covered
 * work.
 */
#ifndef WEBM_H
#define WEBM_H

#include "flow.h"

int32_t parse_webm(flow *f, uint8_t *ptr, uint32_t len);

/* WebM states */

#define WEBM_HEADER 0x01
#define PARSE_ELEMENT 0x02
#define MID_ELEMENT 0x03
#define BLOCK_HEADER 0x04

#endif /* WEBM_H */

