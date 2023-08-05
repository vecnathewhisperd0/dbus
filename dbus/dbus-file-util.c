/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-file-util.c File related helper utility functions
 *
 * Copyright (C) 2020 Ralf Habacker <ralf.habacker@freenet.de>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <config.h>

#include "dbus-file.h"
#include "dbus-internals.h"

/**
 * Copy a file specified by 'from' to the file specified by 'to'
 * and return and error code in case or errors.
 *
 * @param from file path to copy from
 * @param to file path to copy to
 * @param error place to set an error
 * @returns #FALSE if error was set
 *
 * @note This function is intended for copying small files - it's
 * unsuitable for large files that might not fit in memory.
 * (But that's fine for test code.)
 *
 */
dbus_bool_t
_dbus_file_copy (const DBusString *from, const DBusString *to, DBusError *error)
{
  DBusString string;
  dbus_bool_t result = FALSE;

  if (!_dbus_string_init (&string))
    {
      _DBUS_SET_OOM(error);
      return FALSE;
    }

  if (!_dbus_file_get_contents (&string, from, error))
    goto out;

  result = _dbus_string_save_to_file (&string, to, FALSE, error);

out:
  _dbus_string_free (&string);
  return result;
}
