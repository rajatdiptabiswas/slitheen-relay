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
#ifndef HTTP_H
#define HTTP_H

#include "flow.h"

int32_t parse_http(flow *f, uint8_t *ptr, uint32_t len);

int fill_with_downstream(flow *f, uint8_t *data, int32_t length);

/* HTTP states */
#define BEGIN_HEADER 0x10
#define PARSE_HEADER 0x20
#define MID_CONTENT 0x30
#define BEGIN_CHUNK 0x40
#define MID_CHUNK 0x50
#define END_CHUNK 0x60
#define END_BODY 0x70
#define FORFEIT_REST 0x80
#define USE_REST 0x90

/* HTTP content types */
#define UNKNOWN     0x0
#define IMAGE       0x1
#define WEBM        0x2
#define MP4         0x3
#define NOREPLACE   0x4

#endif /* HTTP_H */

