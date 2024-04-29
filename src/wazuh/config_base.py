import typing
import json
import re
from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from typing import Any
from pydantic.fields import FieldInfo
from enum import Enum
from json import JSONDecodeError, JSONEncoder
from .utils import comma_string_to_set
from .opensearch_dsl import OrderBy, Match, Term, Regexp, Wildcard


class EnvSource(EnvSettingsSource):
    """
    Source class with convenience methods for parsing certain complex types
    from environment variables

    Environment variables, or .env files, is expected to be the favourable way
    to configure opencti-wazuh-connector. This works just fine for simple field
    types, but it can be tricky for more complex field types.

    :pydantic:`<>`
    """

    # TODO: possible to stringigy enum names (not values) and match? If not, accept without hyphen?

    def prepare_field_value(
        self, field_name: str, field: FieldInfo, value: Any, value_is_complex: bool
    ) -> Any:
        # If the value is a str and the field is a list[str | Enum] | set[str | Enum]
        if (
            isinstance(value, str)
            and typing.get_origin(field.annotation) in (set, list)
            and len(args := typing.get_args(field.annotation)) == 1
            and ((is_enum := issubclass(args[0], Enum)) or args[0] is str)
        ):
            # First try to load the string as JSON, which is the default
            # pydantic behaviour, and allows for far more expressive syntax:
            try:
                return json.loads(value)

            # If the string is invalid JSON, attempt to parse it as a
            # comma-saparated string of values:
            except JSONDecodeError:
                if typing.get_origin(field.annotation) is list:
                    return re.split(r",\s*", value)
                else:
                    # If the type is an enum, pass it as an argument so that the
                    # special value 'all' can be treated especially (see
                    # comma_string_to_set()):
                    return comma_string_to_set(
                        value.lower(), args[0] if is_enum else None
                    )
        elif (
            isinstance(value, str)
            and typing.get_origin(field.annotation) is list
            and len(args := typing.get_args(field.annotation)) == 1
            and args[0] in (OrderBy, Match, Term, Regexp, Wildcard)
        ):
            try:
                return json.loads(value)
            except JSONDecodeError:
                pairs = [re.split("[:=]", term) for term in re.split(r",\s*", value)]
                if any(len(pair) != 2 for pair in pairs):
                    raise ValueError(
                        f"If not JSON, {field_name} should be a comma-separated string of key=value pairs"
                    )

                def factory(key: str, value: str):
                    if args[0] is OrderBy:
                        return OrderBy(field=key, order=value)
                    elif args[0] in (Match, Regexp, Term, Wildcard):
                        return args[0](field=key, query=value)
                    else:
                        raise ValueError(
                            f"Comma-string representation of {args[0]} not supported"
                        )

                return [factory(key=pair[0], value=pair[1]) for pair in pairs]

        # Let pydantic handle remaining cases:
        return super().prepare_field_value(field_name, field, value, value_is_complex)


class ConfigBase(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WAZUH_", validate_assignment=True)

    # Add a simple dummy method that just makes it clear what's going on:
    @classmethod
    def from_env(cls):
        return cls.model_validate({})

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return super().settings_customise_sources(
            settings_cls,
            init_settings,
            EnvSource(settings_cls),
            EnvSource(settings_cls),
            file_secret_settings,
        )
