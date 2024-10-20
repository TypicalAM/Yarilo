#include "log_sink.h"

namespace yarilo {

std::shared_ptr<ProtoSinkMt> global_proto_sink =
    std::make_shared<ProtoSinkMt>(50);

} // namespace yarilo
