#include <grp.h>
#include <linux/prctl.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

#include <iostream>
#include <string>

/**
 * Switch the process's user and group IDs.
 *
 * @param username New username. If empty, the current user ID is used.
 * @param groupname New groupname. If empty, the current group ID is used.
 *
 * @throws std::runtime_error if the user or group does not exist.
 * @throws std::system_error if setgid or setuid fails.
 */
void switch_user_and_group(std::string username, std::string groupname) {
    struct passwd *pw = nullptr;
    if (username != "") {
        pw = getpwnam(username.c_str());
        if (pw == nullptr) {
            throw std::runtime_error("Error: User " + username + " not found");
        }
    }

    struct group *gr = nullptr;
    if (groupname != "") {
        gr = getgrnam(groupname.c_str());
        if (gr == nullptr) {
            throw std::runtime_error("Error: Group " + groupname + " not found");
        }
    }

    if (gr && setgid(gr->gr_gid) != 0) {
        throw std::system_error(errno, std::system_category(), "Error setting group ID to " + std::to_string(gr->gr_gid));
    }

    if (pw && setuid(pw->pw_uid) != 0) {
        throw std::system_error(errno, std::system_category(), "Error setting user ID to " + std::to_string(pw->pw_uid));
    }

    // Re-enable core dumps.
    // setuid disables core dumps.
    ::prctl(PR_SET_DUMPABLE, 1);

    // Set core dump size to unlimited.
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    ::setrlimit(RLIMIT_CORE, &limit);
}
