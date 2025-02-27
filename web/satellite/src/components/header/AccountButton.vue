// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <div class="account-button-container" id="accountDropdownButton">
        <div class="account-button-toggle-container" @click="toggleSelection">
            <!-- background of this div generated and stores in store -->
            <div class="account-button-toggle-container__avatar">
                <!-- First digit of firstName after Registration -->
                <!-- img if avatar was set -->
                <h1 class="account-button-toggle-container__avatar__letter">{{avatarLetter}}</h1>
            </div>
            <div class="account-button-toggle-container__expander-area">
                <img v-if="!isDropdownShown" src="@/../static/images/account/BlackArrowExpand.svg" alt="Arrow down (expand)"/>
                <img v-if="isDropdownShown" src="@/../static/images/account/BlackArrowHide.svg" alt="Arrow up (hide)"/>
            </div>
        </div>
        <AccountDropdown v-if="isDropdownShown"/>
    </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';

import { APP_STATE_ACTIONS } from '@/utils/constants/actionNames';

import AccountDropdown from './AccountDropdown.vue';

@Component({
    components: {
        AccountDropdown,
    },
})
export default class AccountButton extends Vue {
    public toggleSelection(): void {
        this.$store.dispatch(APP_STATE_ACTIONS.TOGGLE_ACCOUNT);
    }

    public get avatarLetter(): string {
        return this.$store.getters.userName.slice(0, 1).toUpperCase();
    }

    public get isDropdownShown(): boolean {
        return this.$store.state.appStateModule.appState.isAccountDropdownShown;
    }
}
</script>

<style scoped lang="scss">
    .account-button-container {
        position: relative;
        background-color: #FFFFFF;
        cursor: pointer;

        &:hover {

            .account-button-toggle-container__user-name {
                opacity: 0.7;
            }
        }
    }

    .account-button-toggle-container {
        display: flex;
        flex-direction: row;
        align-items: center;
        justify-content: flex-start;
        width: max-content;
        height: 50px;

        &__user-name {
            margin-left: 12px;
            font-family: 'font_medium';
            font-size: 16px;
            line-height: 23px;
            color: #354049;
            transition: opacity .2s ease-in-out;
        }

        &__avatar {
            width: 40px;
            height: 40px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #E8EAF2;

            &__letter {
                font-family: 'font_medium';
                font-size: 16px;
                line-height: 23px;
                color: #354049;
            }
        }

        &__expander-area {
            margin-left: 9px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
    }

    @media screen and (max-width: 1024px) {
        .account-button-toggle-container {

            &__user-name,
            &__expander-area {
                display: none;
            }
        }
    }
</style>