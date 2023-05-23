BMCCACHE_BASE_PATH="$(readlink -f $( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd ))"
BMCCACHE_KERNEL_VERSION="5.8"
BMCCACHE_KERNEL_TARXZ="${BMCCACHE_BASE_PATH}/linux-${BMCCACHE_KERNEL_VERSION}.tar.xz"
BMCCACHE_BMC_PATH="${BMCCACHE_BASE_PATH}/xdp-handler"
