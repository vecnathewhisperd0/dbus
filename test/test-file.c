#include <config.h>
#include "test-utils.h"

#include "dbus/dbus-errors.h"
#include "dbus/dbus-file.h"
#include "dbus/dbus-string.h"
#include "dbus/dbus-types.h"

static dbus_bool_t
file_copy_test (const char *test_data_dir_cstr)
{
  dbus_bool_t result = FALSE;
  DBusError error;
  DBusString src;
  DBusString dest;
  dbus_error_init (&error);
  _dbus_string_init_const (&src, DBUS_SOURCE_DIR "/CMakeLists.txt");
  _dbus_string_init_const (&dest, DBUS_BINARY_DIR "/tempfile");
  result = _dbus_file_copy(&src, &dest, &error);
  if (result)
    result = _dbus_file_exists (_dbus_string_get_const_data (&dest));

  if (result)
    result = _dbus_delete_file (&dest, &error);

  _dbus_string_free (&src);
  _dbus_string_free (&dest);
  return result;
}

static DBusTestCase test = { "file copy", file_copy_test };

int
main (int argc, char **argv)
{
  return _dbus_test_main (argc, argv, 1, &test,
                          (DBUS_TEST_FLAGS_CHECK_MEMORY_LEAKS |
                           DBUS_TEST_FLAGS_CHECK_FD_LEAKS |
                           DBUS_TEST_FLAGS_REQUIRE_DATA),
                           NULL, NULL);
}
