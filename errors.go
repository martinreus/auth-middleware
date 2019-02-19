package auth

var (
    MaxRefreshTimeReached = 1
)

type Error struct {
    ErrorCode int
}

func (err Error) Error() string {
    switch err.ErrorCode {
    case MaxRefreshTimeReached:
        return "Refresh denied; Max Refresh time reached"
    }
    return "Unkown Error"
}
