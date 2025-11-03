# Copyright (c) 2011-2025 Benjamin Fleischer
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# Requires array.sh
# Requires math.sh
# Requires string.sh


declare -a COMMON_LOG_PREFIX=()
declare -i COMMON_LOG_VERBOSE_LEVEL=2


common_log_initialize()
{
    common_log_set_verbose_level ${COMMON_LOG_VERBOSE_LEVEL}
}

common_log_set_verbose_level()
{
    local verbose_level="${1}"

    common_assert "math_is_integer $(string_escape "${verbose_level}")"
    common_assert "(( verbose_level > 0 ))"

    COMMON_LOG_VERBOSE_LEVEL=${verbose_level}

    if (( COMMON_LOG_VERBOSE_LEVEL > 4 ))
    then
        exec 3>&1
        exec 4>&2
    else
        exec 3> /dev/null
        exec 4> /dev/null
    fi
}

common_log()
(
    local -i verbose_level=2
    local    color=""
    local -i trace=0
    local -i trace_offset=0

    common_log_options_handler()
    {
        case "${1}" in
            -v|--verbose-level)
                verbose_level="${2}"
                return 2
                ;;
            -c|--color)
                color="${2}"
                return 2
                ;;
            -t|--trace)
                trace=1
                return 1
                ;;
            -o|--trace-offset)
                trace_offset="${2}"
                return 2
                ;;
        esac
    }

    common_options_parse common_log_options_handler "v:,verbose-level:,c:,color:,t,trace,o:,offset:" "${@}"
    shift ${?}
    unset -f common_log_options_handler

    if (( verbose_level > COMMON_LOG_VERBOSE_LEVEL ))
    then
        return 0
    fi

    if [[ -z "${color}" ]]
    then
        case ${verbose_level} in
            1|2|3)
                color="0;39"
                ;;
            *)
                color="0;2"
                ;;
        esac
    fi

    if (( trace == 1 ))
    then
        local -a stack=()
        local -i i=${trace_offset}
        local    caller=""
        local    function=""
        local    file=""
        local    line=""

        while caller="$(caller ${i})"
        do
            function="$(/usr/bin/cut -d " " -f 2 <<< "${caller}")"
            file="$(/usr/bin/cut -d " " -f 3- <<< "${caller}")"
            line="$(/usr/bin/cut -d " " -f 1 <<< "${caller}")"

            stack+=("at ${function} (${file}, line ${line})")

            (( i++ ))
        done

        set -- "${@}" "${stack[@]}"
    fi

    while (( ${#} > 0 ))
    do
        if (( ${#COMMON_LOG_PREFIX[@]} > 0 ))
        then
            printf "%-30s | " "${COMMON_LOG_PREFIX}" >&2
        fi
        printf "\033[%sm%s\033[0m\n" "${color}" "${1}" >&2
        shift
    done
)

common_log_variable()
(
    while (( ${#} > 0 ))
    do
        common_log -v 4 -- "$(common_variable_print "${1}")"
        shift
    done
)

common_warn()
(
    common_log -v 1 -c "0;31" -o 1 "${@}"
)

common_die()
(
    if (( ${#} == 0 ))
    then
        set -- "Unspecified error"
    fi

    common_log -v 1 -c "1;31" -o 1 "${@}"
    printf "\a" >&2

    if (( BASH_SUBSHELL > 0 ))
    then
        kill -SIGTERM 0
    fi
    exit 1
)

common_assert()
(
    if [[ -n "${1}" ]]
    then
        eval "${1}"
        if (( ${?} != 0 ))
        then
            if [[ -n "${2}" ]]
            then
                common_die -t -o 2 "${2}"
            else
                common_die -t -o 2 "Assertion '${1}' failed"
            fi
        fi
    fi
)

common_die_on_error()
(
    if (( ${?} != 0 ))
    then
        common_die "${@}"
    fi
)

common_warn_on_error()
(
    if (( ${?} != 0 ))
    then
        common_warn "${@}"
    fi
)


common_signal_trap_initialize()
{
    local signal=""
    for signal in SIGINT SIGTERM
    do
        trap "common_signal_trap \"${signal}\"" "${signal}"
    done
}

common_signal_trap()
{
    local signal="${1}"

    common_log -v 4 "Received signal: ${signal}"
    case "${signal}" in
        SIGINT)
            common_warn "Aborted by user"
            exit 130
            ;;
        SIGTERM)
            exit 143
            ;;
        *)
            common_warn "Ignore signal: ${signal}"
            ;;
    esac
}


common_options_parse()
{
    common_assert "[[ ! $(string_escape "${1}") =~ ^common_options_parse_ ]]"

    common_options_parse_internal()
    (
        local -a options=("${1}")

        local -a specs=()
        IFS="," read -ra specs <<< "${2}"

        shift 2

        common_options_parse_preprocess_spec()
        {
            case "${1: -1}" in
                ":")
                    common_variable_set "${2}" "${1:0:$((${#1} - 1))}"
                    common_variable_set "${3}" 1
                    ;;
                "?")
                    common_variable_set "${2}" "${1:0:$((${#1} - 1))}"
                    common_variable_set "${3}" 2
                    ;;
                *)
                    common_variable_set "${2}" "${1}"
                    common_variable_set "${3}" 0
                    ;;
            esac
        }

        local -i count=0

        local    spec_name=""
        local -i spec_has_argument=0

        local    option=""
        local    option_name=""
        local    option_argument=""
        local -i option_has_argument=0

        local -i match_found=0
        local    match_name=""
        local -i match_has_argument=0

        while (( ${#} > 0 ))
        do
            case ${1} in
                --)
                    (( count++ ))
                    break
                    ;;
                -)
                    break
                    ;;
                --*)
                    option="${1:2}"
                    (( count++ ))
                    shift

                    option_name="$(/usr/bin/sed -E -n -e 's/^([^=]*).*$/\1/p' <<< "${option}")"
                    option_argument="$(/usr/bin/sed -E -n -e 's/^[^=]*=(.*)$/\1/p' <<< "${option}")"

                    [[ ! "${option}" =~ "=" ]]
                    option_has_argument=${?}

                    match_found=0
                    match_name=""
                    match_has_argument=0

                    local spec=""
                    for spec in "${specs[@]}"
                    do
                        common_options_parse_preprocess_spec "${spec}" spec_name spec_has_argument

                        if (( ${#spec_name} == 1 ))
                        then
                            continue
                        fi

                        if [[ "${spec_name:0:${#option_name}}" = "${option_name}" ]]
                        then
                            match_name="${spec_name}"
                            match_has_argument=${spec_has_argument}

                            if (( ${#spec_name} == ${#option_name} ))
                            then
                                match_found=1
                                break
                            elif (( match_found != 0 ))
                            then
                                common_die "Option '--${option_name}' is ambiguous"
                                break 2
                            else
                                match_found=1
                            fi
                        fi
                    done
                    if (( match_found == 0 ))
                    then
                        common_die "Illegal option '${option_name}'"
                        break
                    fi
                    if (( match_has_argument != 2 && option_has_argument != match_has_argument ))
                    then
                        if (( option_has_argument == 0 ))
                        then
                            common_die "Option '--${option_name}' requires an argument"
                        else
                            common_die "Option '--${option_name}' does not allow an argument"
                        fi
                        break
                    fi

                    options+=("--${match_name}")
                    if (( match_has_argument != 0 ))
                    then
                        options+=("${option_argument}")
                    fi
                    ;;
                -*)
                    option="${1:1}"
                    (( count++ ))
                    shift

                    option_name="${option:0:1}"
                    option_argument="${option:1}"

                    match_found=0

                    local spec=""
                    for spec in "${specs[@]}"
                    do
                        common_options_parse_preprocess_spec "${spec}" spec_name spec_has_argument

                        if [[ "${option_name}" == "${spec_name}" ]]
                        then
                            match_found=1

                            options+=("-${option_name}")
                            if (( spec_has_argument == 0 ))
                            then
                                if [[ -n "${option_argument}" ]]
                                then
                                    set -- "-${option_argument}" "${@}"
                                fi
                            else
                                if [[ -z "${option_argument}" ]]
                                then
                                    if (( ${#} <= 0 ))
                                    then
                                        common_die "Option '-${option_name}' requires an argument"
                                        break 2
                                    fi
                                    option_argument="${1}"
                                    (( count++ ))
                                    shift
                                fi

                                options+=("${option_argument}")
                            fi
                            break
                        fi
                    done

                    if (( match_found == 0 ))
                    then
                        common_die "Illegal option '-${option_name}'"
                        break
                    fi
                    ;;
                *)
                    break
                    ;;
            esac
        done

        printf "%d" ${count}
        printf " %q" "${options[@]}"
    )

    eval "set -- $(common_options_parse_internal "${@}")"
    unset -f common_options_parse_internal

    # Pass options to handler

    while (( ${#} > 2 ))
    do
        eval "${2}$(printf " %q" "${@:3}")"
        eval "
            if (( ${?} == 0 ))
            then
                common_die \"Option not handled '\${3}'\"
            fi

            set -- \"\${@:1:2}\" \"\${@:3+${?}}\"
        "
    done
    return ${1}
}


common_sudo()
(
    local prompt="${1}"

    common_assert "[[ -n $(string_escape "${prompt}") ]]"
    common_assert "(( ${#} > 1 ))"

    if (( ${#COMMON_LOG_PREFIX[@]} > 0 ))
    then
        prompt="$(printf "%-20s | %s" "${COMMON_LOG_PREFIX}" "${prompt}")"
    fi

    sudo -p "${prompt}: " "${@:2}"
)


common_is_function()
(
    [[ "$(type -t "${1}")" == "function" ]]
)

common_function_is_legal_name()
(
    [[ "${1}" =~ ^[a-zA-Z_][0-9a-zA-Z_]*$ ]]
)

common_function_expand()
(
    while (( ${#} > 0 ))
    do
        declare -F | /usr/bin/cut -c 12- | grep "^${1}"
        shift
    done
)

common_is_variable()
(
    compgen -A variable | grep ^"${1}"$ > /dev/null
)

common_variable_is_legal_name()
(
    [[ "${1}" =~ ^[a-zA-Z_][0-9a-zA-Z_]*$ ]]
)

common_variable_is_readonly()
(
    if common_is_variable "${1}"
    then
        [[ "$(declare -p "${1}" 2> /dev/null)" =~ ^"declare -"[^=]{0,}"r"[^=]{0,}" ${1}=" ]]
    fi
)

common_variable_get()
(
    common_assert "common_is_variable $(string_escape "${1}")"

    string_escape "${!1}"
)

common_variable_set()
{
    common_assert "common_variable_is_legal_name $(string_escape "${1}")"

    eval "${1}=$(string_escape "${2}")"
}

common_variable_clone()
{
    common_assert "common_is_variable $(string_escape "${1}")"

    if [[ -z "${2}" ]]
    then
        declare -p ${1} | /usr/bin/sed -E -n -e 's/^[^=]+ [^= ]+=(.+)$/\1/p'
    elif common_is_variable "${2}"
    then
        eval "$(declare -p ${1} | /usr/bin/sed -E -n -e "s/^[^=]+ [^= ]+=(.+)\$/${2}=\1/p")"
    else
        common_assert "common_variable_is_legal_name $(string_escape "${2}")"

        eval "$(declare -p ${1} | /usr/bin/sed -E -n -e "s/^declare (([+-][a-zA-Z]+ )*)(-- )?([^= ]+)=(.+)\$/declare \1 -g -- ${2}=\5/p")"
    fi
}

common_variable_print()
(
    common_assert "common_is_variable $(string_escape "${1}")"

    declare -p ${1} | /usr/bin/sed -E -n -e 's/^[^=]+ ([^= ]+=.+)$/\1/p'
)

common_variable_require()
(
    while (( ${#} > 0 ))
    do
        if ! common_is_variable "${1}"
        then
            common_die "Variable not declared: ${1}"
        fi
        shift
    done
)

common_variable_expand()
(
    eval "
        common_variable_expand_internal()
        {
            printf \"%s\" \"\${1}\"
            shift
            while (( \${#} > 0 ))
            do
                printf \" %s\" \"\${1}\"
                shift
            done
        }

        common_variable_expand_wrapper()
        {
            common_variable_expand_internal $(printf "\"\${!%s@}\" " "${@}")
        }
    " && common_variable_expand_wrapper
    local -i rc=${?}

    unset -f common_variable_expand_internal
    unset -f common_variable_expand_wrapper
    return ${rc}
)


common_path_absolute()
(
    local path="${1}"

    if [[ ! "${path}" =~ ^/ ]]
    then
        path="$(pwd -P)/${path}"
    fi

    local -a tokens=()
    IFS="/" read -ra tokens <<< "${path:1}"
    local -i tokens_count=${#tokens[@]}

    local -i i=0
    while (( i < ${#tokens[@]} ))
    do
        case "${tokens[${i}]}" in
            .|"")
                unset -v tokens[${i}]
                tokens=("${tokens[@]}")
                ;;
            ..)
                unset -v tokens[$((i - 1))]
                unset -v tokens[${i}]
                tokens=("${tokens[@]}")
                (( i-- ))
                ;;
            *)
                (( i++ ))
                ;;
        esac
    done

    printf "/"
    array_join tokens "/"
)

common_path_relative()
(
    local target="$(common_path_absolute "${1}")"
    local base="$(common_path_absolute "${2}")"

    local -a target_tokens=()
    IFS="/" read -ra target_tokens <<< "${target:1}"
    local -i target_tokens_count=${#target_tokens[@]}

    local -a base_tokens=()
    IFS="/" read -ra base_tokens <<< "${base:1}"
    local -i base_tokens_count=${#base_tokens[@]}

    local -i common_max=0
    common_max=$(math_min ${target_tokens_count} ${base_tokens_count})

    local -i common_count=0
    while (( common_count < common_max )) \
          && [[ "${target_tokens[${common_count}]}" == "${base_tokens[${common_count}]}" ]]
    do
        (( common_count++ ))
    done

    local -a relative=()

    local -i i=0
    for (( ; i < base_tokens_count - common_count ; i++ ))
    do
        relative+=("..")
    done
    relative+=("${target_tokens[@]:${common_count}}")

    printf "./"
    array_join relative "/"
)
