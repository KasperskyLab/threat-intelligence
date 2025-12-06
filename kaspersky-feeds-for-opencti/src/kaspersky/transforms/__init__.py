#!/usr/bin/env python3
#
# © 2024 AO Kaspersky Lab. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Kaspersky transforms module."""
from .actors_transform import ActorsTransform
from .indicators_transform import IndicatorsTransform
from .industries_transform import IndustriesTransform
from .locations_transform import LocationsTransform
from .malwares_transform import MalwaresTransform
from .reports_transform import ReportsTransform
from .observable_transform import ObservableTransform
from .utils import TEMPORAL_ATTRIBUTE_PREFIX
from .utils import extract_first_quoted_word
